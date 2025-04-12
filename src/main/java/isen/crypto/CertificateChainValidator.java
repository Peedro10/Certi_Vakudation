package isen.crypto;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
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
            // Charger tous les certificats
            for (int i = 1; i < args.length; i++) {
                X509Certificate cert = CertificateUtils.loadCertificate(format, args[i]);
                certChain.add(cert);
            }

            System.out.println("\nCertificate Chain Checks :");

            // Vérifier la chaîne dans l'ordre (leaf -> root)
            boolean isChainValid = true;

            // 1. Vérifier les relations entre les certificats
            for (int i = 0; i < certChain.size() - 1; i++) {
                X509Certificate currentCert = certChain.get(i);
                X509Certificate issuerCert = certChain.get(i + 1);

                // Vérifier que l'émetteur correspond au sujet du certificat suivant
                if (!currentCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                    System.out.println(" [X] Invalid subject and issuer for certificate " + args[i+1] + " and " + args[i+2]);
                    isChainValid = false;
                } else {
                    System.out.println(" [OK] Valid subject and issuer for certificate " + args[i+1] + " and " + args[i+2]);
                }
            }

            // 2. Vérifier chaque certificat individuellement
            for (int i = 0; i < certChain.size(); i++) {
                X509Certificate cert = certChain.get(i);
                String certName = args[i+1].substring(args[i+1].lastIndexOf('/') + 1);

                System.out.println("\nCertificate Information for " + certName + " :");
                System.out.println("\tIssuer: " + cert.getIssuerX500Principal().getName());
                System.out.println("\tSubject: " + cert.getSubjectX500Principal().getName());
                System.out.println("\tValidity : " + cert.getNotBefore() + " - " + cert.getNotAfter());

                System.out.println("Checks :");

                // a. Vérification de la signature
                try {
                    if (i == certChain.size() - 1) {
                        // Pour le certificat racine (auto-signé)
                        cert.verify(cert.getPublicKey());
                        System.out.println(" [OK] Certificate signature verified successfully.");
                    } else {
                        // Pour les autres certificats, vérifier avec la clé de l'émetteur
                        cert.verify(certChain.get(i+1).getPublicKey());
                        System.out.println(" [OK] Certificate signature verified successfully.");
                    }
                } catch (Exception e) {
                    System.out.println(" [X] Error: Certificate signature could not be verified.");
                    isChainValid = false;
                }

                // b. Vérification de KeyUsage
                boolean[] keyUsage = cert.getKeyUsage();
                boolean keyUsageValid = false;

                if (keyUsage != null) {
                    // Pour un certificat CA, keyCertSign devrait être true
                    if (i < certChain.size() - 1 && keyUsage.length > 5 && keyUsage[5]) {
                        System.out.println(" [OK] KeyUsage extension verified successfully.");
                        keyUsageValid = true;
                    } else if (i == certChain.size() - 1) {
                        // Pour le certificat feuille, d'autres usages sont acceptables
                        keyUsageValid = true;
                        System.out.println(" [OK] KeyUsage extension verified successfully.");
                    }
                }

                if (!keyUsageValid) {
                    System.out.println(" [X] Error: KeyUsage extension could not be verified.");
                    isChainValid = false;
                }

                // c. Vérification de la période de validité
                try {
                    cert.checkValidity(new Date());
                    System.out.println(" [OK] Validity period verified successfully.");
                } catch (Exception e) {
                    System.out.println(" [X] Error: The certificate is not valid for the current period.");
                    isChainValid = false;
                }

                // d. Vérification de BasicConstraints
                try {
                    byte[] extValue = cert.getExtensionValue("2.5.29.19"); // OID de BasicConstraints

                    boolean isCA = (i < certChain.size() - 1); // Tous sauf le dernier doivent être CA

                    if (isCA && extValue == null) {
                        System.out.println(" [X] Error: BasicConstraints extension could not be verified.");
                        isChainValid = false;
                    } else if (!isCA && extValue == null) {
                        System.out.println(" [X] Error: BasicConstraints extension could not be verified.");
                        // Ne pas invalider pour un certificat feuille
                    } else {
                        System.out.println(" [OK] BasicConstraints extension verified successfully.");
                    }
                } catch (Exception e) {
                    System.out.println(" [X] Error checking BasicConstraints: " + e.getMessage());
                    isChainValid = false;
                }

                // e. Vérification manuelle de la signature (à implémenter pour RSA et ECDSA)
                // Cette partie devrait appeler les méthodes de CryptoUtils
            }

            // Afficher le résultat final de la vérification
            if (isChainValid) {
                System.out.println("\nCertificate chain is valid");
            } else {
                System.out.println("\nCertificate chain is invalid");
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}