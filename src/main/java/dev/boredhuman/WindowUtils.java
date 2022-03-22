package dev.boredhuman;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;

public class WindowUtils {
	public static int getProcessIDByWindowTitle(String title) {
		int[] processIds = new int[1024];
		IntByReference processCountBytes = new IntByReference();

		if (!Psapi.INSTANCE.EnumProcesses(processIds, processIds.length * 4, processCountBytes)) {
			ClassInjector.err("Enum process failed.");
		}

		IntByReference breakFlag = new IntByReference(-1);

		for (int i = 0; i < processCountBytes.getValue() / 4; i++) {
			int processId = processIds[i];

			WinNT.HANDLE handle = Kernel32.INSTANCE.OpenProcess(WinNT.PROCESS_ALL_ACCESS, false, processId);

			if (handle == null) {
				continue;
			}

			User32.INSTANCE.EnumWindows((hwnd, data) -> {
				char[] stringData = new char[260];
				int length = User32.INSTANCE.GetWindowText(hwnd, stringData, 260);

				if (length != 0) {
					String windowName = new String(stringData, 0, length);

					if (windowName.toLowerCase().contains(title.toLowerCase())) {
						User32.INSTANCE.GetWindowThreadProcessId(hwnd, breakFlag);
						return false;
					}
				}

				return true;
			}, Pointer.NULL);

			int breakValue = breakFlag.getValue();
			if (breakValue != -1) {
				Kernel32.INSTANCE.CloseHandle(handle);
				return breakValue;
			}

			Kernel32.INSTANCE.CloseHandle(handle);
		}
		return -1;
	}

	public static boolean getDebugPrivileges() {
		WinNT.HANDLE currentProcess = Kernel32.INSTANCE.GetCurrentProcess();
		WinNT.HANDLEByReference hToken = new WinNT.HANDLEByReference();

		if (!Advapi32.INSTANCE.OpenProcessToken(currentProcess, WinNT.TOKEN_ADJUST_PRIVILEGES, hToken)) {
			ClassInjector.err("Failed to open process token");
			return false;
		}
		WinNT.LUID luid = new WinNT.LUID();

		if (!Advapi32.INSTANCE.LookupPrivilegeValue(null, WinNT.SE_DEBUG_NAME, luid)) {
			ClassInjector.err("Failed to get luid for SeDebugPrivilege");
			return false;
		}

		WinNT.TOKEN_PRIVILEGES tokenPrivileges = new WinNT.TOKEN_PRIVILEGES(1);

		WinNT.LUID_AND_ATTRIBUTES luidAttributes = new WinNT.LUID_AND_ATTRIBUTES(luid, new WinDef.DWORD(WinNT.SE_PRIVILEGE_ENABLED));

		tokenPrivileges.Privileges[0] = luidAttributes;

		if (!Advapi32.INSTANCE.AdjustTokenPrivileges(hToken.getValue(), false, tokenPrivileges, tokenPrivileges.size(), null, null)) {
			ClassInjector.err("Could not adjust process privileges");

			return false;
		}

		Kernel32.INSTANCE.CloseHandle(hToken.getValue());

		return Kernel32.INSTANCE.GetLastError() == 0;
	}
}
