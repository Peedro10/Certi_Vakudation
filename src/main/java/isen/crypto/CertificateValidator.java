package isen.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateValidator {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java CertificateValidator <DER|PEM> <certPath>");
            return;
        }

        String format = args[0];
        String certPath = args[1];

        try {
            X509Certificate certificate = loadCertificate(format, certPath);

            printCenteredTitle("== Certificate Information ==");
            System.out.println("Subject     : " + certificate.getSubjectX500Principal());
            System.out.println("Issuer      : " + certificate.getIssuerX500Principal());
            System.out.println("Valid from  : " + certificate.getNotBefore());
            System.out.println("Valid until : " + certificate.getNotAfter());
            System.out.println();

            // Vérification de la signature (auto-signé)
            try {
                PublicKey publicKey = certificate.getPublicKey();
                certificate.verify(publicKey);
                System.out.println("[OK] Signature is valid (self-signed)");
            } catch (Exception e) {
                System.out.println("[X] Signature verification failed: " + e.getMessage());
            }

            // Vérification KeyUsage
            boolean[] keyUsage = certificate.getKeyUsage();
            // Pour vérifier KeyUsage correctement
            if (keyUsage != null) {
                System.out.println("\nKeyUsage:");
                // Pour un certificat CA, keyCertSign devrait être true
                if (keyUsage.length > 5 && keyUsage[5]) {
                    System.out.println("  [OK] Certificate can sign other certificates (keyCertSign)");
                } else {
                    System.out.println("  [X] Certificate cannot sign other certificates");
                }
                // Autres usages...
            } else {
                System.out.println("[X] KeyUsage extension not found - invalid for a CA certificate.");
            }

            // Pour vérifier BasicConstraints
            try {
                byte[] extValue = certificate.getExtensionValue("2.5.29.19"); // OID de BasicConstraints
                if (extValue != null) {
                    // Parse l'extension pour vérifier si c'est une CA
                    // Utiliser ASN1InputStream de BouncyCastle pour extraire isCA
                    System.out.println("[OK] BasicConstraints extension found");
                } else {
                    System.out.println("[X] BasicConstraints extension not found - invalid for a CA certificate");
                }
            } catch (Exception e) {
                System.out.println("[X] Error checking BasicConstraints: " + e.getMessage());
            }

            // Pour la vérification manuelle avec Signature API
            String sigAlgName = certificate.getSigAlgName();
            System.out.println("\nSignature algorithm: " + sigAlgName);
            try {
                Signature sig = Signature.getInstance(sigAlgName);
                sig.initVerify(certificate.getPublicKey());
                sig.update(certificate.getTBSCertificate());
                boolean valid = sig.verify(certificate.getSignature());
                if (valid) {
                    System.out.println("[OK] Signature manually verified with java.security.Signature API");
                } else {
                    System.out.println("[X] Manual signature verification failed");
                }
            } catch (Exception e) {
                System.out.println("[X] Error in manual signature verification: " + e.getMessage());
            }

            // Vérification de la période de validité
            try {
                certificate.checkValidity();
                System.out.println("\n[OK] Certificate is currently valid.");
            } catch (Exception e) {
                System.out.println("[X] Certificate is not valid: " + e.getMessage());
            }

        } catch (Exception e) {
            System.out.println("[X] Error loading certificate: " + e.getMessage());
        }
    }

    public static X509Certificate loadCertificate(String format, String path) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in;

        if (format.equalsIgnoreCase("DER")) {
            in = new FileInputStream(path);
            return (X509Certificate) factory.generateCertificate(in);
        } else if (format.equalsIgnoreCase("PEM")) {
            String content = Files.readString(new File(path).toPath());
            content = content.replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(content);
            in = new java.io.ByteArrayInputStream(decoded);
            return (X509Certificate) factory.generateCertificate(in);
        } else {
            throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    // Titre centré dans un terminal de 80 caractères
    private static void printCenteredTitle(String title) {
        int width = 80;
        int padding = (width - title.length()) / 2;
        System.out.println(" ".repeat(Math.max(0, padding)) + title);
    }
}