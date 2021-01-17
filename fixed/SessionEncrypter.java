import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Cipher;
import java.security.SecureRandom;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.NoSuchPaddingException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.io.IOException;

class SessionEncrypter {
	private Cipher cipher;
	private SessionKey sessionKey;
	private IvParameterSpec ivKey;

	public SessionEncrypter(Integer keylength)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		cipher = Cipher.getInstance("AES/CTR/NoPadding");
		sessionKey = new SessionKey(keylength);

		SecureRandom rand = new SecureRandom();
		byte[] iv = new byte[cipher.getBlockSize()];
		rand.nextBytes(iv);
		ivKey = new IvParameterSpec(iv);

		cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivKey);
	}

	public SessionEncrypter(byte[] keybytes, byte[] ivbytes)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		cipher = Cipher.getInstance("AES/CTR/NoPadding");
		sessionKey = new SessionKey(keybytes);
		ivKey = new IvParameterSpec(ivbytes);

		cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivKey);
	}

	public byte[] getKeyBytes() {
		return sessionKey.getKeyBytes();
	}

	public byte[] getIVBytes() {
		return ivKey.getIV();
	}

	public CipherOutputStream openCipherOutputStream(OutputStream out) {
		return new CipherOutputStream(out, cipher);
	}

	private static String bytesToHex(byte[] bytes) {
		final char[] HEX = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int i = 0; i < bytes.length; i++) {
			int b = bytes[i] & 0xFF;
			hexChars[i * 2] = HEX[b >> 4];
			hexChars[i * 2 + 1] = HEX[b & 0x0F];
		}
		return new String(hexChars);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		SessionEncrypter se = new SessionEncrypter(256);
		String keyHex = bytesToHex(se.getKeyBytes());
		String ivHex = bytesToHex(se.getIVBytes());
		CipherOutputStream cos = se.openCipherOutputStream(baos);
		cos.write(args[0].getBytes(StandardCharsets.UTF_8));
		String ms = bytesToHex(baos.toByteArray());
		System.out.println("kh: " + keyHex + "\nih: " + ivHex + "\nms: " + ms);
	}
}
