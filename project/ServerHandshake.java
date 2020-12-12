
/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.DataInputStream;
import java.io.IOException;

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

	/**
	 * Run server handshake protocol on a handshake socket. Here, we simulate the
	 * handshake by just creating a new socket with a preassigned port number for
	 * the session.
	 */
	public ServerHandshake(Socket handshakeSocket, String myCert, String caCert) throws IOException {
		DataInputStream dataIn = new DataInputStream(handshakeSocket.getInputStream());

		String state = "ClientHello";
		try {
			while (state != "Finished") {
				String parameter = dataIn.readUTF();
				if (!parameter.equals("MessageType")) {
					System.out.println("Expected: \"MessageType\".\nRecieved: \"" + parameter + "\".");
					throw new IOException();
				}
				final String messageType = dataIn.readUTF();
				if (!messageType.equals(state)) {
					System.out.println("MessageType does not match state.");
					System.out.println("State: " + state + "\nMessageType: " + messageType);
					throw new IOException();
				}
				switch (messageType) {
					case "ClientHello":
						parameter = dataIn.readUTF();
						if (!parameter.equals("Certificate")) {
							System.out.println("Expected : \"Certificate\".\nRecieved: \"" + parameter + "\".");
						}
						final String clientCert = dataIn.readUTF();
						if (!VerifyCertificate.verify(caCert, clientCert)) {
							System.out.println("Client Certificate not verified.");
							throw new IOException();
						}
						System.out.println("Certificate verified");

						break;

					default:
				}

			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		dataIn.close();
	}
}
