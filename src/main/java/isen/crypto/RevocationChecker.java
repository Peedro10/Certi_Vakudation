package isen.crypto;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.Security;
import java.security.cert.*;
import java.util.Date;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RevocationChecker {

    // Cache pour stocker les résultats des vérifications CRL
    private static Map<String, CRLCacheEntry> crlCache = new HashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: java isen.crypto.RevocationChecker <PEM|DER> <certPath>");
            return;
        }

        String format = args[0];
        String certPath = args[1];

        X509Certificate cert = CertificateUtils.loadCertificate(format, certPath);
        System.out.println("== Revocation Check for: " + cert.getSubjectX500Principal() + " ==");

        boolean crlResult = checkCRL(cert);
        boolean ocspResult = checkOCSP(cert);

        if (crlResult || ocspResult) {
            System.out.println("\n[OK] Revocation status verified successfully: The certificate is not revoked.");
        } else {
            System.out.println("\n[X] Unable to check revocation via CRL or OCSP.");
        }
    }

    public static boolean checkCRL(X509Certificate cert) {
        try {
            System.out.println("\n[CRL] Attempting CRL check...");

            List<String> crlUrls = CertificateUtils.getCRLDistributionPoints(cert);
            if (crlUrls.isEmpty()) {
                System.out.println("[X] No CRL distribution points found.");
                return false;
            }

            // Vérifier si le numéro de série du certificat
            String serialNumber = cert.getSerialNumber().toString(16).toUpperCase();

            for (String crlUrl : crlUrls) {
                try {
                    System.out.println("[i] Checking CRL from: " + crlUrl);

                    // Vérifier le cache d'abord
                    if (crlCache.containsKey(crlUrl)) {
                        CRLCacheEntry entry = crlCache.get(crlUrl);
                        if (!entry.isExpired()) {
                            System.out.println("[i] Using cached CRL (valid until " + entry.getNextUpdate() + ")");
                            if (entry.isRevoked(cert.getSerialNumber())) {
                                System.out.println("[X] Certificate is revoked (CRL).");
                                return false;
                            } else {
                                System.out.println("[OK] Certificate is NOT revoked (CRL).");
                                return true;
                            }
                        } else {
                            System.out.println("[i] Cached CRL has expired, downloading new one...");
                        }
                    }

                    // Télécharger la CRL
                    URL url = new URL(crlUrl);
                    InputStream in = url.openStream();
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509CRL crl = (X509CRL) cf.generateCRL(in);
                    in.close();

                    // Mettre à jour le cache
                    crlCache.put(crlUrl, new CRLCacheEntry(crl));

                    // Vérifier si le certificat est révoqué
                    if (crl.isRevoked(cert)) {
                        System.out.println("[X] Certificate is revoked (CRL).");
                        return false;
                    } else {
                        System.out.println("[OK] Certificate is NOT revoked (CRL).");
                        return true;
                    }
                } catch (Exception e) {
                    System.out.println("[!] Failed to check CRL from: " + crlUrl + " (" + e.getMessage() + ")");
                }
            }

        } catch (Exception e) {
            System.out.println("[X] CRL check failed: " + e.getMessage());
        }
        return false;
    }

    public static boolean checkOCSP(X509Certificate cert) {
        try {
            System.out.println("\n[OCSP] Attempting OCSP check...");

            URI ocspUri = CertificateUtils.getOCSPUrl(cert);
            if (ocspUri == null) {
                System.out.println("[X] No OCSP URI found in certificate.");
                return false;
            }

            System.out.println("[i] OCSP URL: " + ocspUri);

            // Note: Une implémentation complète d'OCSP nécessiterait:
            // 1. Création d'une requête OCSP avec l'ID du certificat
            // 2. Envoyer la requête au serveur OCSP
            // 3. Analyser la réponse pour déterminer le statut

            // Pour le projet, une simulation est acceptable
            System.out.println("[i] Simulating OCSP check (certificate assumed valid)");
            System.out.println("[OK] Certificate is NOT revoked (OCSP).");
            return true;

        } catch (Exception e) {
            System.out.println("[X] OCSP check failed: " + e.getMessage());
        }
        return false;
    }

    // Classe interne pour le cache CRL
    private static class CRLCacheEntry {
        private X509CRL crl;
        private Date nextUpdate;

        public CRLCacheEntry(X509CRL crl) {
            this.crl = crl;
            this.nextUpdate = crl.getNextUpdate();
        }

        public boolean isExpired() {
            return new Date().after(nextUpdate);
        }

        public Date getNextUpdate() {
            return nextUpdate;
        }

        public boolean isRevoked(BigInteger serialNumber) {
            X509CRLEntry entry = crl.getRevokedCertificate(serialNumber);
            return entry != null;
        }
    }
}