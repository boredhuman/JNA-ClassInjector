package dev.boredhuman;

public class Example {

	public static void main(String[] args) {
		WindowUtils.getDebugPrivileges();
		int processID = WindowUtils.getProcessIDByWindowTitle("recaf");
		if (processID == -1) {
			return;
		}
		new ClassInjector(RemoteJarLoader.class, processID);
	}
}
