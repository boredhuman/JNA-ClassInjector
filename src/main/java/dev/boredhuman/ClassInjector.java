package dev.boredhuman;

import com.sun.jna.Function;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;

import java.lang.reflect.Proxy;

public class ClassInjector {

	static final int WOW64_CONTEXT_ALL = 0x1003F;

	static NativeLibrary K32 = ((Library.Handler) Proxy.getInvocationHandler(Kernel32.INSTANCE)).getNativeLibrary();
	static Function getThreadContext = ClassInjector.K32.getFunction("GetThreadContext");
	static Function debugActiveProcess = ClassInjector.K32.getFunction("DebugActiveProcess");
	static Function debugActiveProcessStop = ClassInjector.K32.getFunction("DebugActiveProcessStop");
	static Function waitForDebugEvent = ClassInjector.K32.getFunction("WaitForDebugEvent");
	static Function setThreadContext = ClassInjector.K32.getFunction("SetThreadContext");
	static Function continueDebugEvent = ClassInjector.K32.getFunction("ContinueDebugEvent");
	static Function resumeThread = ClassInjector.K32.getFunction("ResumeThread");
	static Function getProcAddress = ClassInjector.K32.getFunction("GetProcAddress");
	static Function suspendThread = ClassInjector.K32.getFunction("SuspendThread");

	public ClassInjector(Class<?> classToLoad, int processID) {
		if (WindowUtils.getDebugPrivileges()) {
			WinNT.HANDLE handle = Kernel32.INSTANCE.OpenProcess(WinNT.PROCESS_ALL_ACCESS, false, processID);

			WinDef.HMODULE[] modules = new WinDef.HMODULE[1024];
			IntByReference bytesWritten = new IntByReference();

			if (!Psapi.INSTANCE.EnumProcessModules(handle, modules, 8 * 1024, bytesWritten)) {
				ClassInjector.err("Could not enumerate modules.");
				return;
			}

			int moduleCount = bytesWritten.getValue() / 8;

			for (int i = 0; i < moduleCount; i++) {
				byte[] buffer = new byte[260];
				if (Psapi.INSTANCE.GetModuleFileNameExA(handle, modules[i], buffer, 260) == 0) {
					ClassInjector.err("Failed to get module file name");
					continue;
				}

				String moduleName = new String(buffer, 0, this.getStringLength(buffer));

				if (!moduleName.contains("jvm.dll")) {
					continue;
				}

				WinDef.HMODULE jvmModule = Kernel32.INSTANCE.LoadLibraryEx(moduleName, null, 1); // DONT_RESOLVE_DLL_REFERENCES

				Memory procName = new Memory("JNI_GetCreatedJavaVMs".getBytes().length + 1);
				procName.setString(0, "JNI_GetCreatedJavaVMs");

				long procAddress = (long) ClassInjector.getProcAddress.invoke(long.class, new Object[] {jvmModule, procName});

				Native.free(Pointer.nativeValue(procName));

				long getCreatedJavaVMsAddress = procAddress - Pointer.nativeValue(jvmModule.getPointer()) + Pointer.nativeValue(modules[i].getPointer());
				// dont need the library anymore
				Kernel32.INSTANCE.FreeLibrary(jvmModule);

				RemoteMemoryHelper memoryHelper = new RemoteMemoryHelper(handle);

				Pointer JVMArrayPointerPointer = memoryHelper.alloc(8);
				// basically the stack position after just before the thread calls the target function

				JNIClassInjectorCallback jniClassInjectorCallback = new JNIClassInjectorCallback(memoryHelper, getCreatedJavaVMsAddress, JVMArrayPointerPointer, classToLoad);
				this.callRemoteThread(handle, processID, Pointer.createConstant(getCreatedJavaVMsAddress), JVMArrayPointerPointer, jniClassInjectorCallback);
				break;
			}

			Kernel32.INSTANCE.CloseHandle(handle);
		}
	}

	public void callRemoteThread(WinNT.HANDLE processHandle, int processID, Pointer methodAddress, Pointer rcx, CallRemoteMethodCallBack callback) {
		WinDef.DWORDByReference threadId = new WinDef.DWORDByReference();
		WinNT.HANDLE thread = Kernel32.INSTANCE.CreateRemoteThread(processHandle, null, 0, methodAddress, rcx, WinNT.CREATE_SUSPENDED, threadId);

		int threadID = threadId.getValue().intValue();

		CONTEXT context = new CONTEXT(thread);

		// set context flags
		context.context.setInt(CONTEXT.CONTEXT_FLAGS, ClassInjector.WOW64_CONTEXT_ALL);

		int status = (int) ClassInjector.getThreadContext.invoke(int.class, new Object[] {thread, context.context});

		if (status == 0) {
			ClassInjector.err("Failed to get thread context error");
		}
		// set hardware breakpoint on our target method
		context.context.setLong(CONTEXT.DR0, Pointer.nativeValue(methodAddress));
		context.context.setLong(CONTEXT.DR7, 1 | 2);
		// start debugging process
		status = (int) ClassInjector.debugActiveProcess.invoke(int.class, new Object[] {processID});

		if (status == 0) {
			ClassInjector.err("Could not debug process error");
		}

		status = (int) ClassInjector.setThreadContext.invoke(int.class, new Object[] {thread, context.context});

		if (status == 0) {
			ClassInjector.err("Could not set thread context error");
		}

		status = (int) ClassInjector.resumeThread.invoke(int.class, new Object[] {thread});

		if (status == -1) {
			ClassInjector.err("Failed to resume thread error");
		}

		Memory debugEvent = new Memory(176);

		while (true) {
			ClassInjector.waitForDebugEvent.invoke(new Object[] {debugEvent, 0xFFFFFFFF});

			int dwDebugEventCode = debugEvent.getInt(0);
			int dwProcessID = debugEvent.getInt(4);
			int dwThreadID = debugEvent.getInt(8);
			// skip debug event if it isn't on our thread
			if (dwDebugEventCode != 1 || dwThreadID != threadID) {
				// DBG_EXCEPTION_NOT_HANDLED
				ClassInjector.continueDebugEvent.invoke(new Object[]{dwProcessID, dwThreadID, 0x80010001});
				continue;
			}
			// get thread context
			status = (int) ClassInjector.getThreadContext.invoke(int.class, new Object[]{thread, context.context});

			if (status == 0) {
				System.out.println("Failed to get thread context error " + ClassInjector.getLastError());
			}

			// pass our args
			boolean exit = callback.modifyContext(context);

			status = (int) ClassInjector.setThreadContext.invoke(int.class, new Object[]{thread, context.context});

			if (status == 0) {
				ClassInjector.err("Failed to set thread context with new params error");
			}
			// DBG_EXCEPTION_HANDLED
			ClassInjector.continueDebugEvent.invoke(new Object[]{dwProcessID, dwThreadID, 0x00010001});

			if (exit) {
				break;
			}
		}

		status = (int) ClassInjector.debugActiveProcessStop.invoke(int.class, new Object[] {processID});

		if (status == 0) {
			ClassInjector.err("Failed to stop debugger error");
		}

		Kernel32.INSTANCE.WaitForSingleObject(thread, 0xFFFFFFFF);
		Kernel32.INSTANCE.CloseHandle(thread);

		Native.free(Pointer.nativeValue(debugEvent));
		Native.free(Pointer.nativeValue(context.context));
	}

	public interface CallRemoteMethodCallBack {
		// return true if you want to exit
		boolean modifyContext(CONTEXT context);
	}

	public static void err(String error) {
		System.out.println(error + ClassInjector.getLastError());
	}

	public static String getLastError() {
		return " Error code: " + Kernel32.INSTANCE.GetLastError();
	}

	public int getStringLength(byte[] string) {
		int length = 0;
		while (length < string.length && string[length] != 0) {
			length++;
		}
		return length;
	}
}
