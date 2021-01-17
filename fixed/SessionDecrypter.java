import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.Cipher;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.NoSuchPaddingException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.io.IOException;

class SessionDecrypter {
	private Cipher cipher;
	private SessionKey sessionKey;
	private IvParameterSpec ivKey;

	public SessionDecrypter(byte[] keybytes, byte[] ivbytes)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		cipher = Cipher.getInstance("AES/CTR/NoPadding");
		sessionKey = new SessionKey(keybytes);
		ivKey = new IvParameterSpec(ivbytes);

		cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivKey);
	}

	public CipherInputStream openCipherInputStream(InputStream in) {
		return new CipherInputStream(in, cipher);
	}

	private static byte[] hexToBytes(String hex) {
		final char[] HEX = "0123456789ABCDEF".toCharArray();
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++)
			bytes[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4) + Character.digit(hex.charAt(i * 2 + 1), 16));
		return bytes;
	}

	public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException {
		byte[] kb = hexToBytes(args[0]);
		byte[] iv = hexToBytes(args[1]);
		byte[] ms = hexToBytes(args[2]);
		SessionDecrypter sd = new SessionDecrypter(kb, iv);
		ByteArrayInputStream bais = new ByteArrayInputStream(ms);
		CipherInputStream cis = sd.openCipherInputStream(bais);
		System.out.println(new String(cis.readAllBytes(), StandardCharsets.UTF_8));
	}
}
