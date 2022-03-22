package dev.boredhuman;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinNT;

import java.lang.reflect.Method;

public class CONTEXT {
	public static final int RSP = 152;
	public static final int CONTEXT_FLAGS = 48;
	public static final int DR0 = 72;
	public static final int DR7 = 112;
	public static final int RIP = 248;
	public static final int RAX = 120;
	public static final int RCX = 128;
	public static final int RDX = 136;
	public static final int R8 = 184;
	public static final int R9 = 192;


	public Memory context = new Memory(1232);
	public WinNT.HANDLE threadHandle;

	public CONTEXT(WinNT.HANDLE threadHandle) {
		this.threadHandle = threadHandle;
	}

	public void setLong(long offset, long value) {
		this.context.setLong(offset, value);
	}
	// returns null otherwise a runnable to clean up the stack
	public Runnable setParameters(RemoteMemoryHelper memoryHelper, Pointer... args) {
		Runnable stackCleaner = null;

		if (args.length > 4) {
			int extraParams = args.length - 4;
			int extraParamAligned = extraParams;
			// keep stack pointer 16 byte aligned
			if (extraParamAligned % 2 == 1) {
				extraParamAligned += 1;
			}
			// increase stack
			long stackPtr = this.context.getLong(CONTEXT.RSP);
			long returnAddr = memoryHelper.readLong(stackPtr);
			long newStackPtr = stackPtr - (extraParamAligned * 8L);
			this.context.setLong(CONTEXT.RSP, newStackPtr);
			// move return address down
			memoryHelper.writeLong(newStackPtr, returnAddr);

			for (int i = 0; i < extraParams; i++) {
				Pointer arg = args[4 + i];
				// 40 offset due to shadow space and return address
				memoryHelper.writeLong(newStackPtr + 40 + (i * 8L), Pointer.nativeValue(arg));
			}

			stackCleaner = () -> {
				// restore original state
				this.context.setLong(CONTEXT.RSP, stackPtr);
				memoryHelper.writeLong(stackPtr, returnAddr);
			};
		}

		for (int i = 0; i < 4 && i < args.length; i++) {
			Pointer arg = args[i];
			int registerOffset;
			switch (i) {
				case 0:
					registerOffset = CONTEXT.RCX;
					break;
				case 1:
					registerOffset = CONTEXT.RDX;
					break;
				case 2:
					registerOffset = CONTEXT.R8;
					break;
				case 3:
					registerOffset = CONTEXT.R9;
					break;
				default:
					throw new IllegalStateException("Unexpected value: " + i);
			}

			long argValue = Pointer.nativeValue(arg);
			this.context.setLong(registerOffset, argValue);
		}
		return stackCleaner;
	}
}
