import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
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

	public static X509Certificate getCertString(String cert) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getBytes()));
	}

	public static void verify(X509Certificate caCert, X509Certificate usrCert) throws CertificateException {
		try {
			caCert.checkValidity();
			usrCert.checkValidity();
			caCert.verify(caCert.getPublicKey());
			usrCert.verify(caCert.getPublicKey());
			System.out.println("Pass");
		} catch (Exception e) {
			System.out.println("Fail");
			throw new CertificateException();
		}
	}

	public static boolean verify(String caCert, String usrCert) {
		try {
			X509Certificate caCertificate = getCertString(caCert);
			X509Certificate usrCertificate = getCertString(usrCert);

			caCertificate.checkValidity();
			usrCertificate.checkValidity();
			caCertificate.verify(caCertificate.getPublicKey());
			usrCertificate.verify(caCertificate.getPublicKey());
		} catch (Exception e) {
			return false;
		}
		return true;
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
