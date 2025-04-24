package isen.crypto;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Classe utilitaire pour les opérations cryptographiques avancées
 * Contient des méthodes pour la vérification manuelle des signatures
 */
public class CryptoUtils {

    static {
        // Ajout du provider BouncyCastle pour le support des opérations cryptographiques avancées
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Vérifie la signature d'un certificat en utilisant l'API java.security.Signature
     * Cette méthode extrait les données TBS (To Be Signed) et la signature du certificat
     * puis utilise l'API Signature pour vérifier la signature
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public static boolean verifySignatureAdvanced(X509Certificate cert, PublicKey publicKey) {
        try {
            // Extraire l'algorithme de signature
            String sigAlgName = cert.getSigAlgName();
            
            // Créer l'instance de Signature avec l'algorithme approprié
            Signature signature = Signature.getInstance(sigAlgName);
            
            // Initialiser avec la clé publique pour la vérification
            signature.initVerify(publicKey);
            
            // Mettre à jour avec les données à vérifier (TBS Certificate)
            signature.update(cert.getTBSCertificate());
            
            // Vérifier la signature
            boolean isValid = signature.verify(cert.getSignature());
            
            return isValid;
        } catch (Exception e) {
            System.out.println("Erreur lors de la vérification avancée: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Vérifie manuellement une signature RSA en utilisant BigInteger
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public static boolean verifyRSASignatureManually(X509Certificate cert, PublicKey publicKey) {
        try {
            // Vérifier que la clé publique est bien une clé RSA
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new Exception("La clé publique fournie n'est pas une clé RSA");
            }
            
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            
            // 1. Extraire les données TBS (To Be Signed) du certificat
            byte[] tbsCertificate = cert.getTBSCertificate();
            
            // 2. Extraire la signature du certificat
            byte[] signatureBytes = cert.getSignature();
            BigInteger signature = new BigInteger(1, signatureBytes);
            
            // 3. Récupérer l'algorithme de signature et le hash correspondant
            String sigAlgName = cert.getSigAlgName();
            String hashAlgorithm = getHashAlgorithmName(sigAlgName);
            
            // 4. Calculer le hash des données TBS
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            byte[] tbsHash = md.digest(tbsCertificate);
            
            // 5. Récupérer le modulus et l'exposant de la clé publique
            BigInteger modulus = rsaPublicKey.getModulus();
            BigInteger publicExponent = rsaPublicKey.getPublicExponent();
            
            // 6. Déchiffrer la signature avec la clé publique
            // En RSA, la vérification consiste à déchiffrer la signature avec la clé publique
            // et comparer le résultat au hash des données
            BigInteger decryptedSignature = signature.modPow(publicExponent, modulus);
            
            // 7. Extraire le hash de la signature déchiffrée
            byte[] extractedHash = extractHashFromPKCS1Signature(decryptedSignature.toByteArray(), hashAlgorithm);
            
            // 8. Comparer les hash
            return Arrays.equals(tbsHash, extractedHash);
            
        } catch (Exception e) {
            System.out.println("Erreur lors de la vérification manuelle RSA: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Vérifie manuellement une signature ECDSA en utilisant les courbes elliptiques
     * Note: Cette implémentation est simplifiée et utilise l'API Signature en arrière-plan
     * au lieu d'implémenter manuellement l'algorithme ECDSA complet
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public static boolean verifyECDSASignatureManually(X509Certificate cert, PublicKey publicKey) {
        try {
            // Vérifier que la clé publique est bien une clé EC
            if (!(publicKey instanceof ECPublicKey)) {
                throw new Exception("La clé publique fournie n'est pas une clé EC");
            }
            
            // Pour simplifier et éviter les problèmes de compatibilité avec BouncyCastle,
            // nous allons extraire les composants r et s de la signature ASN.1
            // mais utiliser l'API Signature pour la vérification effective
            
            // 1. Extraire les données TBS (To Be Signed) du certificat
            byte[] tbsCertificate = cert.getTBSCertificate();
            
            // 2. Récupérer l'algorithme de signature
            String sigAlgName = cert.getSigAlgName();
            
            // 3. Extraire les composants r et s de la signature ASN.1 (pour information)
            byte[] signatureBytes = cert.getSignature();
            BigInteger[] rsValues = extractRSFromSignature(signatureBytes);
            
            // 4. Afficher les composants r et s pour démontrer l'extraction
            System.out.println("  Composant r de la signature ECDSA: " + rsValues[0].toString().substring(0, 20) + "...");
            System.out.println("  Composant s de la signature ECDSA: " + rsValues[1].toString().substring(0, 20) + "...");
            
            // 5. Utiliser l'API Signature pour la vérification effective
            Signature signature = Signature.getInstance(sigAlgName);
            signature.initVerify(publicKey);
            signature.update(tbsCertificate);
            return signature.verify(signatureBytes);
            
        } catch (Exception e) {
            System.out.println("Erreur lors de la vérification manuelle ECDSA: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Extrait les composants r et s d'une signature ECDSA
     * 
     * @param signatureBytes Les octets de la signature
     * @return Un tableau contenant r et s
     */
    private static BigInteger[] extractRSFromSignature(byte[] signatureBytes) throws Exception {
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(signatureBytes));
        DERSequence sequence = (DERSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        
        ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
        ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);
        
        return new BigInteger[] { r.getPositiveValue(), s.getPositiveValue() };
    }
    
    /**
     * Extrait le hash d'une signature PKCS#1 déchiffrée
     * 
     * @param decryptedSignature La signature déchiffrée
     * @param hashAlgorithm L'algorithme de hash utilisé
     * @return Le hash extrait
     */
    private static byte[] extractHashFromPKCS1Signature(byte[] decryptedSignature, String hashAlgorithm) throws Exception {
        // Dans PKCS#1, la signature déchiffrée contient un préfixe ASN.1 avec l'identifiant de l'algorithme
        // puis le hash lui-même. Cette méthode extrait le hash.
        
        // Obtenir la taille attendue du hash en fonction de l'algorithme
        int hashSize;
        switch (hashAlgorithm) {
            case "SHA-1":
                hashSize = 20;
                break;
            case "SHA-256":
                hashSize = 32;
                break;
            case "SHA-384":
                hashSize = 48;
                break;
            case "SHA-512":
                hashSize = 64;
                break;
            default:
                throw new Exception("Algorithme de hash non supporté: " + hashAlgorithm);
        }
        
        // Pour simplifier, on suppose que le hash est à la fin des données déchiffrées
        // Dans une implémentation réelle, il faudrait parser la structure ASN.1 complète
        if (decryptedSignature.length < hashSize) {
            throw new Exception("Signature déchiffrée trop courte pour contenir un hash de taille " + hashSize);
        }
        
        byte[] extractedHash = new byte[hashSize];
        System.arraycopy(decryptedSignature, decryptedSignature.length - hashSize, extractedHash, 0, hashSize);
        
        return extractedHash;
    }
    
    /**
     * Extrait le nom de l'algorithme de hash à partir du nom de l'algorithme de signature
     * 
     * @param sigAlgName Le nom de l'algorithme de signature
     * @return Le nom de l'algorithme de hash
     */
    private static String getHashAlgorithmName(String sigAlgName) throws Exception {
        if (sigAlgName.contains("SHA1") || sigAlgName.contains("SHA-1")) {
            return "SHA-1";
        } else if (sigAlgName.contains("SHA256") || sigAlgName.contains("SHA-256")) {
            return "SHA-256";
        } else if (sigAlgName.contains("SHA384") || sigAlgName.contains("SHA-384")) {
            return "SHA-384";
        } else if (sigAlgName.contains("SHA512") || sigAlgName.contains("SHA-512")) {
            return "SHA-512";
        } else {
            throw new Exception("Algorithme de signature non supporté: " + sigAlgName);
        }
    }
    
    /**
     * Détermine le type d'algorithme de signature utilisé (RSA ou ECDSA)
     * 
     * @param cert Le certificat à analyser
     * @return "RSA", "ECDSA" ou "UNKNOWN" selon l'algorithme utilisé
     */
    public static String getSignatureAlgorithmType(X509Certificate cert) {
        String sigAlgName = cert.getSigAlgName();
        
        if (sigAlgName.contains("RSA")) {
            return "RSA";
        } else if (sigAlgName.contains("ECDSA")) {
            return "ECDSA";
        } else {
            return "UNKNOWN";
        }
    }
}