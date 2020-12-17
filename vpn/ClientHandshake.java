
/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.Base64;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ClientHandshake {
	/*
	 * The parameters below should be learned by the client through the handshake
	 * protocol.
	 */

	/* Session host/port */
	public static String sessionHost = "localhost";
	public static int sessionPort = 12345;

	/* Security parameters key/iv should also go here. Fill in! */
	SessionEncrypter sessionEncrypter;
	SessionDecrypter sessionDecrypter;

	/**
	 * Run client handshake protocol on a handshake socket. Here, we do nothing, for
	 * now.
	 */
	public ClientHandshake(Socket handshakeSocket, Arguments arguments) throws Exception {
		String myCertificate = "";
		String caCertificate = "";
		try {
			myCertificate = new String(Files.readAllBytes(Paths.get(arguments.get("usercert"))));
			caCertificate = new String(Files.readAllBytes(Paths.get(arguments.get("cacert"))));
		} catch (IOException e) {
			e.printStackTrace();
		}
		handshakeSocket.setSoTimeout(1000);
		DataInputStream dataIn = new DataInputStream(handshakeSocket.getInputStream());
		DataOutputStream dataOut = new DataOutputStream(handshakeSocket.getOutputStream());
		String parameter;
		String messageType;
		boolean successfulHandshake = false;

		String encodedEncryptedString;
		byte[] encrypedBytes;
		byte[] keyBytes;
		byte[] ivBytes;

		try {
			// ClientHello
			// - Send ClientHello
			dataOut.writeUTF("MessageType");
			dataOut.writeUTF("ClientHello");
			dataOut.writeUTF("Certificate");
			dataOut.writeUTF(myCertificate);
			dataOut.flush();
			// ClientHello complete; All data sent

			// ServerHello
			// - Get Parameter "MessageType"
			parameter = dataIn.readUTF();
			if (!parameter.equals("MessageType")) {
				System.out.println();
				throw new InvalidMessageException("Expected: \"MessageType\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get MessageType "ServerHello"
			messageType = dataIn.readUTF();
			if (!messageType.equals("ServerHello")) {
				System.out.println();
				throw new InvalidMessageException("Expected: \"ServerHello\".\nRecieved: \"" + messageType + "\".");
			}
			// - Get Parameter "Certificate"
			parameter = dataIn.readUTF();
			if (!parameter.equals("Certificate")) {
				throw new InvalidMessageException("Expected : \"Certificate\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get ServerCertificate
			final String serverCertificate = dataIn.readUTF();
			if (!VerifyCertificate.verify(caCertificate, serverCertificate)) {
				throw new InvalidMessageException("Client Certificate not verified.");
			}
			// ServerHello complete; ServerCertificate verified

			// Forward
			dataOut.writeUTF("MessageType");
			dataOut.writeUTF("Forward");
			dataOut.writeUTF("TargetHost");
			dataOut.writeUTF(arguments.get("targethost"));
			dataOut.writeUTF("TargetPort");
			dataOut.writeUTF(arguments.get("targetport"));
			dataOut.flush();
			// Forward complete; All data sent

			// Session
			// - Get PrivateKey from file
			PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
			// - Get Parameter "MessageType"
			parameter = dataIn.readUTF();
			if (!parameter.equals("MessageType")) {
				throw new InvalidMessageException("Expected: \"MessageType\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get MessageType "Session"
			messageType = dataIn.readUTF();
			if (!messageType.equals("Session")) {
				throw new InvalidMessageException("Expected: \"Session\".\nRecieved: \"" + messageType + "\".");
			}
			// - Get Parameter "SessionKey"
			parameter = dataIn.readUTF();
			if (!parameter.equals("SessionKey")) {
				throw new InvalidMessageException("Expected : \"SessionKey\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get SessionKey
			encodedEncryptedString = dataIn.readUTF();
			// - - - Might need error handling
			encrypedBytes = Base64.getDecoder().decode(encodedEncryptedString);
			// - - - Might need error handling
			keyBytes = HandshakeCrypto.decrypt(encrypedBytes, privateKey);
			// - Get Parameter "SessionIV"
			parameter = dataIn.readUTF();
			if (!parameter.equals("SessionIV")) {
				throw new InvalidMessageException("Expected : \"SessionIV\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get SessionKey
			encodedEncryptedString = dataIn.readUTF();
			// - - - Might need error handling
			encrypedBytes = Base64.getDecoder().decode(encodedEncryptedString);
			// - - - Might need error handling
			ivBytes = HandshakeCrypto.decrypt(encrypedBytes, privateKey);
			// - Create SessionEncrypter and SessionDecrypter
			// - - - Might need error handling
			sessionEncrypter = new SessionEncrypter(keyBytes, ivBytes);
			sessionDecrypter = new SessionDecrypter(keyBytes, ivBytes);
			// - Get Parameter "SessionHost"
			parameter = dataIn.readUTF();
			if (!parameter.equals("SessionHost")) {
				throw new InvalidMessageException("Expected : \"SessionHost\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get SessionHost
			// - - - Might want to verify host name
			sessionHost = dataIn.readUTF();
			// - Get Parameter "SessionPort"
			parameter = dataIn.readUTF();
			if (!parameter.equals("SessionPort")) {
				throw new InvalidMessageException("Expected : \"SessionPort\".\nRecieved: \"" + parameter + "\".");
			}
			// - Get SessionPort
			// - - - Might want to verify port
			sessionPort = Integer.parseInt(dataIn.readUTF());
			// Session complete; All data recived

			// Mark handshake as success
			successfulHandshake = true;

		} catch (SocketTimeoutException e) {
			System.out.println("Timeout: Handshake session expired.");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Key is invalid");
			e.printStackTrace();
		} catch (InvalidMessageException e) {
			System.out.println("Invalid message");
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		dataOut.close();
		dataIn.close();

		if (!successfulHandshake) {
			throw new Exception("Handshake Failed");
		}
	}
}
