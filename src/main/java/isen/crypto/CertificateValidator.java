package isen.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.PublicKey;
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
            if (keyUsage != null) {
                System.out.println("\nKeyUsage:");
                String[] usages = {
                        "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                        "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
                };
                for (int i = 0; i < keyUsage.length; i++) {
                    if (keyUsage[i]) {
                        System.out.println("  [OK] " + usages[i]);
                    }
                }
            } else {
                System.out.println("[X] KeyUsage extension not found.");
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
