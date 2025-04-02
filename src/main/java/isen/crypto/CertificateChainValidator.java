package isen.crypto;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateChainValidator {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java CertificateChainValidator <DER|PEM> <cert1> <cert2> ... <certN>");
            return;
        }

        String format = args[0];
        List<X509Certificate> certChain = new ArrayList<>();

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            // Charger tous les certificats
            for (int i = 1; i < args.length; i++) {
                InputStream in = new FileInputStream(args[i]);
                X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
                certChain.add(cert);
            }

            System.out.println("\n===== Certificate Chain Validation =====");

            for (int i = 0; i < certChain.size() - 1; i++) {
                X509Certificate subjectCert = certChain.get(i);
                X509Certificate issuerCert = certChain.get(i + 1);

                System.out.println("\n => Validating certificate:");
                System.out.println("Subject : " + subjectCert.getSubjectX500Principal());
                System.out.println("Issuer  : " + subjectCert.getIssuerX500Principal());

                // Vérification manuelle de la signature
                try {
                    PublicKey issuerKey = issuerCert.getPublicKey();
                    Signature sig = Signature.getInstance(subjectCert.getSigAlgName());
                    sig.initVerify(issuerKey);
                    sig.update(subjectCert.getTBSCertificate());
                    boolean valid = sig.verify(subjectCert.getSignature());

                    if (valid) {
                        System.out.println("[OK] Signature manually verified with java.security.Signature.");
                    } else {
                        System.out.println("[X] Manual signature verification failed.");
                    }
                } catch (Exception e) {
                    System.out.println("[X] Error verifying signature: " + e.getMessage());
                }

                // Vérifie que l'émetteur correspond au sujet suivant
                if (!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                    System.out.println("[X] Issuer does not match subject of next certificate.");
                } else {
                    System.out.println("[OK] Issuer matches subject of next certificate.");
                }
            }

            // Vérifie si le dernier certificat est auto-signé
            X509Certificate last = certChain.get(certChain.size() - 1);
            System.out.println("\n => Root Certificate:");
            System.out.println("Subject : " + last.getSubjectX500Principal());

            try {
                last.verify(last.getPublicKey());
                System.out.println("[OK] Root certificate is self-signed.");
            } catch (Exception e) {
                System.out.println("[X] Root certificate is not self-signed: " + e.getMessage());
            }

        } catch (Exception e) {
            System.out.println(" Error: " + e.getMessage());
        }
    }
}
