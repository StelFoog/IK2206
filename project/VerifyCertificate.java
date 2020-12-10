import java.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

class VerifyCertificate {

	public static X509Certificate getCert(String certFile) throws CertificateException, FileNotFoundException {
		InputStream file = new FileInputStream(certFile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(file);

		return cert;
	}

	public static void verify(X509Certificate caCert, X509Certificate usrCert) {
		try {
			caCert.checkValidity();
			usrCert.checkValidity();
			caCert.verify(usrCert.getPublicKey());
			usrCert.verify(caCert.getPublicKey());
			System.out.println("Pass");
		} catch (Exception e) {
			System.out.println("Fail");

			// TODO: handle exception
		}
	}

	public static void main(String args[]) throws CertificateException, FileNotFoundException {
		String caFile = args[0];
		String usrFile = args[1];

		X509Certificate caCert = getCert(caFile);
		X509Certificate usrCert = getCert(usrFile);

		System.out.println(caCert.getSubjectDN());
		System.out.println(usrCert.getSubjectDN());

		verify(caCert, usrCert);
	}
}
