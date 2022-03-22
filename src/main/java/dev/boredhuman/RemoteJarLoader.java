package dev.boredhuman;

// I would recommend if you want to use this properly to extend classloader and use it to bootstrap loading a jar from the internet
public class RemoteJarLoader {
	public static void init() {
		System.out.println("Hello from the other side");
	}
}
