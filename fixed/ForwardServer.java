
/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import java.lang.AssertionError;
import java.lang.Integer;
import java.lang.IllegalArgumentException;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.StringTokenizer;

public class ForwardServer {
	private static final boolean ENABLE_LOGGING = true;
	public static final int DEFAULTHANDSHAKEPORT = 2206;
	public static final String DEFAULTHANDSHAKEHOST = "localhost";
	public static final String PROGRAMNAME = "ForwardServer";
	private static Arguments arguments;

	private ServerHandshake serverHandshake;
	private ServerSocket handshakeListenSocket;

	/**
	 * Do handshake negotiation with client to authenticate and learn target
	 * host/port, etc.
	 */
	private boolean doHandshake(Socket handshakeSocket) throws UnknownHostException, IOException, Exception {
		String myCert = "";
		String caCert = "";
		try {
			myCert = new String(Files.readAllBytes(Paths.get(arguments.get("usercert"))));
			caCert = new String(Files.readAllBytes(Paths.get(arguments.get("cacert"))));
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			serverHandshake = new ServerHandshake(handshakeSocket, myCert, caCert);
			System.out.println("Successful Handshake");
		} catch (Exception e) {
			System.out.println("Handshake Failed");
			e.printStackTrace();
			return false;
		}
		return true;
	}

	/**
	 * Starts the forward server - binds on a given port and starts serving
	 */
	public void startForwardServer()
			// throws IOException
			throws Exception {

		// Bind server on given TCP port
		int port = Integer.parseInt(arguments.get("handshakeport"));
		ServerSocket handshakeListenSocket;
		try {
			handshakeListenSocket = new ServerSocket(port);
		} catch (IOException ioex) {
			throw new IOException("Unable to bind to port " + port + ": " + ioex);
		}

		log("Nakov Forward Server started on TCP port " + handshakeListenSocket.getLocalPort());

		// Accept client connections and process them until stopped
		while (true) {

			Socket handshakeSocket = handshakeListenSocket.accept();
			String clientHostPort = handshakeSocket.getInetAddress().getHostName() + ":" + handshakeSocket.getPort();
			Logger.log("Incoming handshake connection from " + clientHostPort);

			boolean successfulHandshake = doHandshake(handshakeSocket);
			handshakeSocket.close();
			if (!successfulHandshake)
				continue;
			/*
			 * Set up port forwarding between an established session socket to target
			 * host/port.
			 *
			 */

			ForwardServerClientThread forwardThread;
			forwardThread = new ForwardServerClientThread(serverHandshake.sessionSocket, serverHandshake.targetHost,
					serverHandshake.targetPort, serverHandshake.sessionEncrypter, serverHandshake.sessionDecrypter, true);
			forwardThread.start();
		}
	}

	/**
	 * Prints given log message on the standart output if logging is enabled,
	 * otherwise ignores it
	 */
	public void log(String aMessage) {
		if (ENABLE_LOGGING)
			System.out.println(aMessage);
	}

	static void usage() {
		String indent = "";
		System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
		System.err.println(indent + "Where options are:");
		indent += "    ";
		System.err.println(indent + "--handshakeport=<portnumber>");
		System.err.println(indent + "--usercert=<filename>");
		System.err.println(indent + "--cacert=<filename>");
		System.err.println(indent + "--key=<filename>");
	}

	/**
	 * Program entry point. Reads settings, starts check-alive thread and the
	 * forward server
	 */
	public static void main(String[] args) throws Exception {
		try {
			arguments = new Arguments();
			arguments.setDefault("handshakeport", Integer.toString(DEFAULTHANDSHAKEPORT));
			arguments.setDefault("handshakehost", DEFAULTHANDSHAKEHOST);
			arguments.loadArguments(args);

			if (arguments.get("handshakeport") == null) {
				throw new IllegalArgumentException("Handshake port not specified");
			}
			if (arguments.get("usercert") == null) {
				throw new IllegalArgumentException("User certificate not specified");
			}
			if (arguments.get("cacert") == null) {
				throw new IllegalArgumentException("CA certificate not specified");
			}
			if (arguments.get("key") == null) {
				throw new IllegalArgumentException("Private key not specified");
			}
		} catch (IllegalArgumentException ex) {
			System.out.println(ex);
			usage();
			System.exit(1);
		}
		try {
			VerifyCertificate.verify(VerifyCertificate.getCert(arguments.get("cacert")),
					VerifyCertificate.getCert(arguments.get("usercert")));
		} catch (Exception e) {
			System.out.println("Certificates not verified");
			System.out.println(e);
			System.exit(1);
		}

		ForwardServer srv = new ForwardServer();
		srv.startForwardServer();
	}

}
