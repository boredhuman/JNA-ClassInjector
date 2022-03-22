package dev.boredhuman;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.List;

public class JNIClassInjectorCallback implements ClassInjector.CallRemoteMethodCallBack {

	RemoteMemoryHelper memoryHelper;
	int functionIndex;

	long getCreatedJavaVMsAddress;
	Pointer RCXParam;
	Pointer JVMCountPointer;
	long JVMPointer;
	long fullStackAddress;
	long exitThreadAddress;
	long JNIInvokeInterfacePointer;

	Pointer JNIEnvPointerPointer;
	long JNINativeInterfacePtr;
	long JNIEnvPointer;

	long definedClassPtr;

	List<Pointer> remoteAllocatedMemory = new ArrayList<>();
	Runnable stackCleaner;
	Class<?> classToLoad;

	public JNIClassInjectorCallback(RemoteMemoryHelper remoteMemoryHelper, long getCreatedJavaVMsAddress, Pointer RCXParam, Class<?> classToLoad) {
		this.memoryHelper = remoteMemoryHelper;
		this.getCreatedJavaVMsAddress = getCreatedJavaVMsAddress;
		this.RCXParam = RCXParam;
		this.remoteAllocatedMemory.add(RCXParam);
		this.classToLoad = classToLoad;
	}

	@Override
	public boolean modifyContext(CONTEXT context) {
		long rip = context.context.getLong(CONTEXT.RIP);
		if (rip == this.getCreatedJavaVMsAddress) {
			// start of call to getCreatedJavaVMs
			this.fullStackAddress = context.context.getLong(CONTEXT.RSP);

			this.exitThreadAddress = this.memoryHelper.readLong(this.fullStackAddress);

			context.setLong(CONTEXT.DR0, this.exitThreadAddress);

			this.JVMCountPointer = this.memoryHelper.alloc(4);

			this.remoteAllocatedMemory.add(this.JVMCountPointer);

			context.setParameters(this.memoryHelper, this.RCXParam, new Pointer(1), this.JVMCountPointer);
		} else if (rip == this.exitThreadAddress) {
			switch (this.functionIndex) {
				case 0: {
					// returning from getCreatedJavaVMs
					this.JVMPointer = this.memoryHelper.readLong(this.RCXParam);

					int JVMCount = this.memoryHelper.readInt(this.JVMCountPointer);

					this.JNIInvokeInterfacePointer = this.memoryHelper.readLong(this.JVMPointer);

					long attachCurrentThreadFunctionPtr = this.JNIInvokeInterfacePointer + 32;

					long attachCurrentThreadFunction = this.memoryHelper.readLong(attachCurrentThreadFunctionPtr);

					this.JNIEnvPointerPointer = this.memoryHelper.alloc(8);

					this.remoteAllocatedMemory.add(this.JNIEnvPointerPointer);

					context.setLong(CONTEXT.RIP, attachCurrentThreadFunction);
					context.setLong(CONTEXT.RSP, this.fullStackAddress);
					context.setParameters(this.memoryHelper, new Pointer(this.JVMPointer), this.JNIEnvPointerPointer, Pointer.NULL);
				}
				break;
				case 1: {
					// returning from attachCurrentThread
					this.JNIEnvPointer = this.memoryHelper.readLong(this.JNIEnvPointerPointer);

					this.JNINativeInterfacePtr = this.memoryHelper.readLong(this.JNIEnvPointer);

					long defineClassFunctionPtr = this.JNINativeInterfacePtr + 40;

					long defineClassFunction = this.memoryHelper.readLong(defineClassFunctionPtr);

					context.setLong(CONTEXT.RIP, defineClassFunction);

					byte[] classBytes = ClassUtils.getClassBytes(this.classToLoad);

					Memory classBytesMemory = new Memory(classBytes.length);

					Pointer remoteClassBytesPtr = this.memoryHelper.alloc((int) classBytesMemory.size());
					classBytesMemory.write(0, classBytes, 0, classBytes.length);

					this.memoryHelper.write(remoteClassBytesPtr, classBytesMemory);
					Native.free(Pointer.nativeValue(classBytesMemory));

					this.remoteAllocatedMemory.add(remoteClassBytesPtr);

					context.context.setLong(CONTEXT.RSP, this.fullStackAddress);

					this.stackCleaner = context.setParameters(this.memoryHelper, new Pointer(this.JNIEnvPointer), Pointer.NULL, Pointer.NULL, remoteClassBytesPtr, new Pointer(classBytes.length));
				}
				break;
				case 2: {
					// returning from defineClass clean stack as last method call had more than 4 params
					if (this.stackCleaner != null) {
						this.stackCleaner.run();
					}

					this.definedClassPtr = context.context.getLong(CONTEXT.RAX);

					long getStaticMethodIDFunctionPtr = this.JNINativeInterfacePtr + 904;

					long getStaticMethodIDFunction = this.memoryHelper.readLong(getStaticMethodIDFunctionPtr);

					Pointer methodNamePtr = this.memoryHelper.allocWriteString("init");

					Pointer methodSignaturePtr = this.memoryHelper.allocWriteString("()V");

					this.remoteAllocatedMemory.add(methodNamePtr);
					this.remoteAllocatedMemory.add(methodSignaturePtr);

					context.setLong(CONTEXT.RIP, getStaticMethodIDFunction);
					context.setParameters(this.memoryHelper, new Pointer(this.JNIEnvPointer), new Pointer(this.definedClassPtr), methodNamePtr, methodSignaturePtr);
				}
				break;
				case 3: {
					// return from getStaticMethodID
					long jMethodIDPtr = context.context.getLong(CONTEXT.RAX);

					long callStaticVoidMethodFunctionPtr = this.JNINativeInterfacePtr + 1128;

					long callStaticVoidMethodFunction = this.memoryHelper.readLong(callStaticVoidMethodFunctionPtr);

					context.setLong(CONTEXT.RIP, callStaticVoidMethodFunction);
					context.setLong(CONTEXT.RSP, this.fullStackAddress);
					context.setParameters(this.memoryHelper, new Pointer(this.JNIEnvPointer), new Pointer(this.definedClassPtr), new Pointer(jMethodIDPtr));
				}
				break;
				case 4: {
					// returning from callStaticVoidMethod
					long detachCurrentThreadFunctionPtr = this.JNIInvokeInterfacePointer + 40;

					long detachCurrentThreadFunction = this.memoryHelper.readLong(detachCurrentThreadFunctionPtr);

					context.setLong(CONTEXT.RIP, detachCurrentThreadFunction);
					context.setLong(CONTEXT.RSP, this.fullStackAddress);
					context.setParameters(this.memoryHelper, new Pointer(this.JVMPointer));
				}
				break;
				case 5: {
					// returning from detachCurrentThread
					// clear debug registers and release allocated memory
					context.setLong(CONTEXT.DR0, 0);
					context.setLong(CONTEXT.DR7, 0);
					this.releaseMemory();
					return true;
				}
			}

			this.functionIndex++;
		}

		return false;
	}

	public void releaseMemory() {
		for (Pointer pointer : this.remoteAllocatedMemory) {
			this.memoryHelper.free(pointer);
		}
	}
}
