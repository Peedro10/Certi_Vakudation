package isen.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.Principal;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

/**
 * Classe utilitaire pour la gestion des certificats X.509
 * Cette classe contient des méthodes pour charger et afficher les informations des certificats
 */
public class CertificateUtils {

    static {
        // Ajout du provider BouncyCastle pour le support des opérations cryptographiques avancées
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Charge un certificat X.509 à partir d'un fichier au format DER ou PEM
     * 
     * @param filePath Chemin du fichier contenant le certificat
     * @param format Format du certificat ("DER" ou "PEM")
     * @return L'objet X509Certificate représentant le certificat
     * @throws Exception Si une erreur survient lors du chargement du certificat
     */
    public static X509Certificate loadCertificate(String filePath, String format) throws Exception {
        if (format.equalsIgnoreCase("DER")) {
            return loadCertificateDER(filePath);
        } else if (format.equalsIgnoreCase("PEM")) {
            return loadCertificatePEM(filePath);
        } else {
            throw new IllegalArgumentException("Format non supporté: " + format + ". Utilisez DER ou PEM.");
        }
    }

    /**
     * Charge un certificat X.509 au format DER à partir d'un fichier
     * 
     * @param filePath Chemin du fichier au format DER
     * @return L'objet X509Certificate représentant le certificat
     * @throws Exception Si une erreur survient lors du chargement du certificat
     */
    private static X509Certificate loadCertificateDER(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Charge un certificat X.509 au format PEM à partir d'un fichier
     * Méthode simplifiée utilisant la lecture directe du fichier PEM
     * 
     * @param filePath Chemin du fichier au format PEM
     * @return L'objet X509Certificate représentant le certificat
     * @throws Exception Si une erreur survient lors du chargement du certificat
     */
    private static X509Certificate loadCertificatePEM(String filePath) throws Exception {
        // Lire tout le contenu du fichier
        byte[] content;
        try (FileInputStream fis = new FileInputStream(filePath)) {
            content = fis.readAllBytes();
        }
        
        // Convertir le contenu en chaîne
        String strContent = new String(content);
        
        // Supprimer les en-têtes et pieds de page du PEM
        String cleanContent = strContent
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        
        // Décoder en base64
        byte[] derBytes = Base64.getDecoder().decode(cleanContent);
        
        // Créer le certificat
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
    }

    /**
     * Affiche les informations principales d'un certificat
     * 
     * @param cert Le certificat à analyser
     * @param filename Le nom du fichier (pour l'affichage)
     */
    public static void displayCertificateInfo(X509Certificate cert, String filename) {
        System.out.println("Certificate Information for " + filename + " :");
        
        // Informations de l'émetteur
        Principal issuer = cert.getIssuerDN();
        System.out.println("    Issuer: " + issuer.getName());
        
        // Informations du sujet
        Principal subject = cert.getSubjectDN();
        System.out.println("    Subject: " + subject.getName());
        
        // Période de validité
        Date notBefore = cert.getNotBefore();
        Date notAfter = cert.getNotAfter();
        SimpleDateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy");
        System.out.println("    Validity : " + dateFormat.format(notBefore) + " - " + dateFormat.format(notAfter));
        
        // Algorithme de signature
        String sigAlgName = cert.getSigAlgName();
        System.out.println("    Signature Algorithm: " + sigAlgName);
        
        // Numéro de série
        System.out.println("    Serial Number: " + cert.getSerialNumber());
        
        // Version
        System.out.println("    Version: " + cert.getVersion());

        System.out.println();
    }
    
    /**
     * Extrait le nom du fichier à partir d'un chemin complet
     * 
     * @param filePath Le chemin complet du fichier
     * @return Le nom du fichier sans le chemin
     */
    public static String extractFileName(String filePath) {
        int lastSeparatorIndex = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'));
        if (lastSeparatorIndex == -1) {
            return filePath;
        }
        return filePath.substring(lastSeparatorIndex + 1);
    }
    
    /**
     * Vérifie simplement si un certificat est valide à la date actuelle
     * 
     * @param cert Le certificat à vérifier
     * @return true si le certificat est valide, false sinon
     */
    public static boolean isValidCertificate(X509Certificate cert) {
        try {
            Date now = new Date();
            cert.checkValidity(now);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}