
/**
 * Server side of the handshake.
 */

import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Base64;

import java.net.ServerSocket;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;

public class ServerHandshake {
	/*
	 * The parameters below should be learned by the server through the handshake
	 * protocol.
	 */

	/* Session host/port, and the corresponding ServerSocket */
	public static ServerSocket sessionSocket;
	public static String sessionHost;
	public static int sessionPort;

	/* The final destination -- simulate handshake with constants */
	public static String targetHost = "localhost";
	public static int targetPort = 6789;

	/* Security parameters key/iv should also go here. Fill in! */
	SessionEncrypter sessionEncrypter;
	SessionDecrypter sessionDecrypter;

	/**
	 * Run server handshake protocol on a handshake socket. Here, we simulate the
	 * handshake by just creating a new socket with a preassigned port number for
	 * the session.
	 */
	public ServerHandshake(Socket handshakeSocket, final String myCert, final String caCertificate) throws Exception {
		handshakeSocket.setSoTimeout(1000);
		DataInputStream dataIn = new DataInputStream(handshakeSocket.getInputStream());
		DataOutputStream dataOut = new DataOutputStream(handshakeSocket.getOutputStream());
		String parameter;
		String messageType;
		boolean successfulHandshake = false;

		HandshakeMessage msg = new HandshakeMessage();

		try {
			// ClientHello
			msg.recv(handshakeSocket);
			// - Get Parameter "MessageType"
			if (!msg.getParameter("MessageType").equals("ClientHello")) {
				throw new InvalidMessageException(
						"Expected: \"MessageType\".\nRecieved: \"" + msg.getParameter("MessageType") + "\".");
			}
			// - Get Parameter "Certificate"
			StringBuilder clientCertificate = new StringBuilder(VerifyCertificate.beginCert);
			clientCertificate.append(msg.getParameter("Certificate"));
			clientCertificate.append(VerifyCertificate.endCert);
			if (!VerifyCertificate.verify(caCertificate, clientCertificate.toString())) {
				throw new InvalidMessageException("Client Certificate not verified.");
			}
			System.out.println("ClientHello complete");
			// ClientHello complete; ClientCertificate verified

			// ServerHello
			// - Send ServerHello
			msg.setProperty("MessageType", "ServerHello");
			msg.setProperty("Certificate",
					myCert.replace(VerifyCertificate.beginCert, "").replace(VerifyCertificate.endCert, "").replace("\n", ""));
			msg.send(handshakeSocket);
			System.out.println("ServerHello complete");
			// ServerHello complete; All data sent

			// Forward
			msg.recv(handshakeSocket);
			// - Get Parameter "MessageType", "Forward"
			if (!msg.getParameter("MessageType").equals("Forward")) {
				throw new InvalidMessageException(
						"Expected: \"MessageType\".\nRecieved: \"" + msg.getParameter("MessageType") + "\".");
			}

			// - Get Parameter "TargetHost"
			// - - - Maybe do some verification of host before assigning it
			targetHost = msg.getParameter("TargetHost");
			// - Get Parameter "TargetPort"
			// - - - Maybe do some verification of port before assigning it
			targetPort = Integer.parseInt(msg.getParameter("TargetPort"));
			System.out.println("Forward complete");
			// Forward complete; All forwarding data recived

			// Session
			msg = new HandshakeMessage(); // This is needed for some reason, kinda wacky
			// - Create SessionEncrypter and SessionDecrypter
			try {
				sessionEncrypter = new SessionEncrypter(128);
			} catch (Exception e) {
				System.out.println("Failed to create SessionEncrypter");
				throw e;
			}
			final byte[] keyBytes = sessionEncrypter.getKeyBytes();
			final byte[] ivBytes = sessionEncrypter.getIVBytes();
			try {
				sessionDecrypter = new SessionDecrypter(keyBytes, ivBytes);
			} catch (Exception e) {
				System.out.println("Failed to create SessionDecrypter");
				throw e;
			}
			// - Encrypt keyBytes and ivBytes
			PublicKey clientPublic = VerifyCertificate.getCertString(clientCertificate.toString()).getPublicKey();
			final byte[] encryptedKeyBytes = HandshakeCrypto.encrypt(keyBytes, clientPublic);
			final byte[] encryptedIVBytes = HandshakeCrypto.encrypt(ivBytes, clientPublic);
			// - Create session socket
			// - - Might need exception handling
			sessionSocket = new ServerSocket(0);
			sessionHost = sessionSocket.getInetAddress().getHostName();
			sessionPort = sessionSocket.getLocalPort();
			// - Send Session
			msg.putParameter("MessageType", "Session");
			msg.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedKeyBytes));
			msg.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIVBytes));
			msg.putParameter("SessionHost", sessionHost);
			msg.putParameter("SessionPort", "" + sessionPort);
			msg.send(handshakeSocket);
			System.out.println("Session complete");
			// Session complete; All data sent

			// Mark handshake as success
			successfulHandshake = true;

		} catch (SocketTimeoutException e) {
			System.out.println("Timeout: Handshake session expired.");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Client public key is invalid");
			e.printStackTrace();
		} catch (InvalidMessageException e) {
			System.out.println("Invalid message");
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			// Might want to do more exception handling using the message sent
			System.out.println(e.getMessage());
			e.printStackTrace();
		}

		// try {
		// // ClientHello
		// // - Get Parameter "MessageType"
		// parameter = dataIn.readUTF();
		// if (!parameter.equals("MessageType")) {
		// throw new InvalidMessageException("Expected: \"MessageType\".\nRecieved: \""
		// + parameter + "\".");
		// }
		// // - Get MessageType "ClientHello"
		// messageType = dataIn.readUTF();
		// if (!messageType.equals("ClientHello")) {
		// throw new InvalidMessageException("Expected: \"ClientHello\".\nRecieved: \""
		// + messageType + "\".");
		// }
		// // - Get Parameter "Certificate"
		// parameter = dataIn.readUTF();
		// if (!parameter.equals("Certificate")) {
		// throw new InvalidMessageException("Expected : \"Certificate\".\nRecieved: \""
		// + parameter + "\".");
		// }
		// // - Get ClientCertificate
		// final String clientCertificate = dataIn.readUTF();
		// if (!VerifyCertificate.verify(caCertificate, clientCertificate)) {
		// throw new InvalidMessageException("Client Certificate not verified.");
		// }
		// // ClientHello complete; ClientCertificate verified

		// // ServerHello
		// // - Send ServerHello
		// dataOut.writeUTF("MessageType");
		// dataOut.writeUTF("ServerHello");
		// dataOut.writeUTF("Certificate");
		// dataOut.writeUTF(myCert);
		// dataOut.flush();
		// // ServerHello complete; All data sent

		// // Forward
		// // - Get Parameter "MessageType"
		// parameter = dataIn.readUTF();
		// if (!parameter.equals("MessageType")) {
		// throw new InvalidMessageException("Expected: \"MessageType\".\nRecieved: \""
		// + parameter + "\".");
		// }
		// // - Get MessageType "Forward"
		// messageType = dataIn.readUTF();
		// if (!messageType.equals("Forward")) {
		// throw new InvalidMessageException("Expected: \"Forward\".\nRecieved: \"" +
		// messageType + "\".");
		// }
		// // - Get Parameter "TargetHost"
		// parameter = dataIn.readUTF();
		// if (!parameter.equals("TargetHost")) {
		// throw new InvalidMessageException("Expected : \"TargetHost\".\nRecieved: \""
		// + parameter + "\".");
		// }
		// // - Get TargetHost
		// // - - - Maybe do some verification of host before assigning it
		// targetHost = dataIn.readUTF();
		// // - Get Parameter "TargetPort"
		// parameter = dataIn.readUTF();
		// if (!parameter.equals("TargetPort")) {
		// throw new InvalidMessageException("Expected : \"TargetPort\".\nRecieved: \""
		// + parameter + "\".");
		// }
		// // - Get TargetPort
		// // - - - Maybe do some verification of port before assigning it
		// targetPort = Integer.parseInt(dataIn.readUTF());
		// // Forward complete; All forwarding data recived

		// // Session
		// // - Create SessionEncrypter and SessionDecrypter
		// try {
		// sessionEncrypter = new SessionEncrypter(128);
		// } catch (Exception e) {
		// System.out.println("Failed to create SessionEncrypter");
		// throw e;
		// }
		// final byte[] keyBytes = sessionEncrypter.getKeyBytes();
		// final byte[] ivBytes = sessionEncrypter.getIVBytes();
		// try {
		// sessionDecrypter = new SessionDecrypter(keyBytes, ivBytes);
		// } catch (Exception e) {
		// System.out.println("Failed to create SessionDecrypter");
		// throw e;
		// }
		// // - Encrypt keyBytes and ivBytes
		// PublicKey clientPublic =
		// VerifyCertificate.getCertString(clientCertificate).getPublicKey();
		// final byte[] encryptedKeyBytes = HandshakeCrypto.encrypt(keyBytes,
		// clientPublic);
		// final byte[] encryptedIVBytes = HandshakeCrypto.encrypt(ivBytes,
		// clientPublic);
		// // - Create session socket
		// // - - Might need exception handling
		// sessionSocket = new ServerSocket(0);
		// sessionHost = sessionSocket.getInetAddress().getHostName();
		// sessionPort = sessionSocket.getLocalPort();
		// // - Send Session
		// dataOut.writeUTF("MessageType");
		// dataOut.writeUTF("Session");
		// dataOut.writeUTF("SessionKey");
		// dataOut.writeUTF(Base64.getEncoder().encodeToString(encryptedKeyBytes));
		// dataOut.writeUTF("SessionIV");
		// dataOut.writeUTF(Base64.getEncoder().encodeToString(encryptedIVBytes));
		// dataOut.writeUTF("SessionHost");
		// dataOut.writeUTF(sessionHost);
		// dataOut.writeUTF("SessionPort");
		// dataOut.writeUTF("" + sessionPort);
		// dataOut.flush();
		// // Session complete; All data sent

		// // Mark handshake as success
		// successfulHandshake = true;

		// } catch (SocketTimeoutException e) {
		// System.out.println("Timeout: Handshake session expired.");
		// e.printStackTrace();
		// } catch (InvalidKeyException e) {
		// System.out.println("Client public key is invalid");
		// e.printStackTrace();
		// } catch (InvalidMessageException e) {
		// System.out.println("Invalid message");
		// System.out.println(e.getMessage());
		// e.printStackTrace();
		// } catch (Exception e) {
		// // Might want to do more exception handling using the message sent
		// System.out.println(e.getMessage());
		// e.printStackTrace();
		// }
		dataIn.close();
		dataOut.close();
		if (!successfulHandshake) {
			throw new Exception("Handshake Failed");
		}
	}
}
