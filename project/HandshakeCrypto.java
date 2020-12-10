import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

class HandshakeCrypto {
	public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphertext);
	}

	public static PublicKey getPublicKeyFromCertFile(String certfile) throws FileNotFoundException, CertificateException {
		InputStream inStream = new FileInputStream(certfile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

		return cert.getPublicKey();
	}

	public static PrivateKey getPrivateKeyFromKeyFile(String keyfile)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] bytes = Files.readAllBytes(Paths.get(keyfile));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
		return kf.generatePrivate(keySpec);
	}

	// Abandoned: Too much garbage to complete
	//
	// private static String getPEMKey(String keyfile) throws FileNotFoundException,
	// IOException {
	// StringBuilder sb = new StringBuilder();
	// BufferedReader br = new BufferedReader(new FileReader(keyfile));
	// String line;
	// while ((line = br.readLine()) != null)
	// sb.append(line);
	// br.close();

	// String pemKey = sb.toString().replace("-----BEGIN RSA PRIVATE KEY-----", "");
	// return pemKey.replace("-----END RSA PRIVATE KEY-----", "");
	// }

	// public static PrivateKey getPrivateKeyFromKeyFile(String keyfile)
	// throws FileNotFoundException, IOException, NoSuchAlgorithmException,
	// InvalidKeySpecException {
	// String pemKey = getPEMKey(keyfile);
	// System.out.println(pemKey);
	// byte[] encoded = Base64.getDecoder().decode(pemKey);
	// KeyFactory kf = KeyFactory.getInstance("RSA");
	// PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
	// RSAPrivateCrtKeySpec keySpec
	// return kf.generatePrivate(keySpec);
	// }
}
