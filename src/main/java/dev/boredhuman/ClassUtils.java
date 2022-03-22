package dev.boredhuman;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class ClassUtils {
	public static byte[] getClassBytes(Class<?> klass) {
		String classLocation = klass.getName().replace(".", "/") + ".class";
		try (InputStream classStream = ClassInjector.class.getClassLoader().getResourceAsStream(classLocation)) {
			if (classStream == null) {
				return null;
			}
			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			byte[] buffer = new byte[1024];
			int read;

			while((read = classStream.read(buffer)) != -1) {
				bos.write(buffer, 0, read);
			}

			return bos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
