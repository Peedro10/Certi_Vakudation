package isen.crypto;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java isen.crypto.Main <command> <certPath>");
            System.out.println("Commands:");
            System.out.println("  test-utils        Test certificate utilities");
            System.out.println("  validate-cert     Validate a single certificate");
            System.out.println("  validate-chain    Validate a certificate chain");
            return;
        }

        String command = args[0];
        String certPath = args[1];

        try {
            if (command.equals("test-utils")) {
                testCertificateUtils(certPath);
            } else if (command.equals("validate-cert")) {
                // Appel à CertificateValidator
                String[] validatorArgs = new String[2];
                validatorArgs[0] = "DER"; // ou déterminer automatiquement
                validatorArgs[1] = certPath;
                CertificateValidator.main(validatorArgs);
            } else if (command.equals("validate-chain")) {
                // Appel à CertificateChainValidator (besoin d'au moins 2 certificats)
                if (args.length < 3) {
                    System.out.println("Error: validate-chain requires at least 2 certificates");
                    return;
                }
                String[] chainArgs = new String[args.length - 1];
                chainArgs[0] = "DER"; // ou déterminer automatiquement
                for (int i = 1; i < args.length - 1; i++) {
                    chainArgs[i] = args[i + 1];
                }
                CertificateChainValidator.main(chainArgs);
            } else {
                System.out.println("Unknown command: " + command);
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void testCertificateUtils(String certPath) {
        try {
            System.out.println("\n===== Testing CertificateUtils =====");
            System.out.println("Loading certificate: " + certPath);

            // Charger le certificat
            X509Certificate cert = CertificateUtils.loadCertificate("DER", certPath);

            System.out.println("\nCertificate Information:");
            System.out.println("  Subject: " + cert.getSubjectX500Principal().getName());
            System.out.println("  Issuer: " + cert.getIssuerX500Principal().getName());
            System.out.println("  Valid from: " + cert.getNotBefore());
            System.out.println("  Valid until: " + cert.getNotAfter());

            // Tester l'extraction CRL
            System.out.println("\nCRL Distribution Points:");
            List<String> crlUrls = CertificateUtils.getCRLDistributionPoints(cert);
            if (crlUrls.isEmpty()) {
                System.out.println("  No CRL distribution points found");
            } else {
                for (String url : crlUrls) {
                    System.out.println("  " + url);
                }
            }

            // Tester l'extraction OCSP
            System.out.println("\nOCSP Responder URL:");
            URI ocspUrl = CertificateUtils.getOCSPUrl(cert);
            if (ocspUrl == null) {
                System.out.println("  No OCSP responder URL found");
            } else {
                System.out.println("  " + ocspUrl);
            }

            System.out.println("\nTest completed successfully");

        } catch (Exception e) {
            System.out.println("Error testing CertificateUtils: " + e.getMessage());
            e.printStackTrace();
        }
    }
}