package dev.boredhuman;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT;

import java.util.function.Consumer;

class RemoteMemoryHelper {
	WinNT.HANDLE processHandle;

	public RemoteMemoryHelper(WinNT.HANDLE processHandle) {
		this.processHandle = processHandle;
	}

	public Pointer alloc(int size) {
		BaseTSD.SIZE_T allocSize = new BaseTSD.SIZE_T(size);
		return Kernel32.INSTANCE.VirtualAllocEx(this.processHandle, null, allocSize, WinNT.MEM_COMMIT, WinNT.PAGE_READWRITE);
	}

	public Pointer allocWriteString(String string) {
		byte[] data = string.getBytes();
		Pointer stringLocation = this.alloc(data.length + 1);
		Memory stringBuffer = new Memory(data.length);
		stringBuffer.write(0, data, 0, data.length);
		this.write(stringLocation, stringBuffer);
		Native.free(Pointer.nativeValue(stringBuffer));
		return stringLocation;
	}

	public void read(Pointer address, Memory buffer) {
		if (!Kernel32.INSTANCE.ReadProcessMemory(this.processHandle, address, buffer, (int) buffer.size(), null)) {
			ClassInjector.err("Could not read process memory");
		}
	}

	public int readInt(Pointer address) {
		Memory intBuffer = new Memory(4);
		this.read(address, intBuffer);
		int value = intBuffer.getInt(0);
		Native.free(Pointer.nativeValue(intBuffer));
		return value;
	}

	public long readLong(long address) {
		return this.readLong(new Pointer(address));
	}

	public long readLong(Pointer address) {
		Memory longBuffer = new Memory(8);
		this.read(address, longBuffer);
		long value = longBuffer.getLong(0);
		Native.free(Pointer.nativeValue(longBuffer));
		return value;
	}

	public void write(Pointer address, Memory buffer) {
		if (!Kernel32.INSTANCE.WriteProcessMemory(this.processHandle, address, buffer, (int) buffer.size(), null)) {
			ClassInjector.err("Failed to write process memory");
		}
	}

	public void writeLong(long address, long value) {
		this.writeLong(new Pointer(address), value);
	}

	public void writeLong(Pointer address, long value) {
		Memory buffer = new Memory(8);
		buffer.setLong(0, value);
		this.write(address, buffer);
		Native.free(Pointer.nativeValue(buffer));
	}

	public void free(Pointer address) {
		if (!Kernel32.INSTANCE.VirtualFreeEx(this.processHandle, address, null, WinNT.MEM_RELEASE)) {
			ClassInjector.err("Failed to free process memory");
		}
	}
}
