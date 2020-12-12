
/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.security.cert.X509Certificate;
import java.io.DataOutputStream;
import java.io.IOException;
import javax.crypto.spec.IvParameterSpec;

public class ClientHandshake {
	/*
	 * The parameters below should be learned by the client through the handshake
	 * protocol.
	 */

	/* Session host/port */
	public static String sessionHost = "localhost";
	public static int sessionPort = 12345;

	/* Security parameters key/iv should also go here. Fill in! */
	private static SessionKey sessionKey;
	private static IvParameterSpec ivKey;

	/**
	 * Run client handshake protocol on a handshake socket. Here, we do nothing, for
	 * now.
	 */
	public ClientHandshake(Socket handshakeSocket, String cert) throws IOException {
		DataOutputStream dataOut = new DataOutputStream(handshakeSocket.getOutputStream());
		dataOut.writeUTF("MessageType");
		dataOut.writeUTF("ClientHello");
		dataOut.writeUTF("Certificate");
		dataOut.writeUTF(cert);
		dataOut.flush();

		dataOut.close();
	}
}
