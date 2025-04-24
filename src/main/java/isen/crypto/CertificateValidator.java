package isen.crypto;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Classe pour la validation d'un certificat X.509
 * Implémente différentes vérifications sur un certificat individuel
 */
public class CertificateValidator {
    
    // Instance du vérificateur de révocation
    private RevocationChecker revocationChecker;
    
    /**
     * Constructeur initialisant le vérificateur de révocation
     */
    public CertificateValidator() {
        this.revocationChecker = new RevocationChecker();
    }

    /**
     * Valide un certificat en effectuant toutes les vérifications disponibles
     * 
     * @param cert Le certificat à valider
     * @return true si le certificat passe toutes les vérifications, false sinon
     */
    public boolean validateCertificate(X509Certificate cert) {
        return validateCertificate(cert, null);
    }
    
    /**
     * Valide un certificat en effectuant toutes les vérifications disponibles
     * 
     * @param cert Le certificat à valider
     * @param issuerCert Le certificat de l'émetteur (peut être null)
     * @return true si le certificat passe toutes les vérifications, false sinon
     */
    public boolean validateCertificate(X509Certificate cert, X509Certificate issuerCert) {
        boolean isValid = true;
        
        // Afficher les résultats des différentes vérifications
        System.out.println("\nChecks :");
        
        // 1. Vérification de la période de validité
        if (!verifyValidityPeriod(cert)) {
            System.out.println("[X] Error: The certificate is not valid for the current period.");
            isValid = false;
        } else {
            System.out.println("[OK] Certificate is valid for current date.");
        }
        
        // 2. Vérification de la signature (classique)
        PublicKey keyToUse = (issuerCert != null) ? issuerCert.getPublicKey() : cert.getPublicKey();
        if (!verifySignature(cert, keyToUse)) {
            System.out.println("[X] Error: Certificate signature could not be verified (standard check).");
            isValid = false;
        } else {
            System.out.println("[OK] Certificate signature verified successfully (standard check).");
        }
        
        // 3. Vérification avancée de la signature
        if (!verifySignatureAdvanced(cert, keyToUse)) {
            System.out.println("[X] Error: Certificate signature could not be verified (advanced check).");
            isValid = false;
        } else {
            System.out.println("[OK] Certificate signature verified successfully (advanced check).");
        }
        
        // 4. Vérification de l'extension KeyUsage
        if (!verifyKeyUsage(cert)) {
            System.out.println("[X] Error: KeyUsage extension could not be verified.");
            isValid = false;
        } else {
            System.out.println("[OK] KeyUsage extension verified successfully.");
        }
        
        // 5. Vérification de l'extension BasicConstraints
        boolean isSelfSigned = isSelfSigned(cert);
        if (!verifyBasicConstraints(cert, isSelfSigned)) {
            System.out.println("[X] Error: BasicConstraints extension could not be verified.");
            // Si c'est un certificat auto-signé ou racine, nous considérons que c'est une erreur critique
            if (isSelfSigned) {
                isValid = false;
            } else {
                // Pour un certificat non auto-signé (comme un certificat feuille),
                // nous l'indiquons mais ne le rendons pas pénalisant
                System.out.println("  (Note: This is not critical for non-CA certificates)");
            }
        } else {
            System.out.println("[OK] BasicConstraints extension verified successfully.");
        }
        
        // 6. Vérification du statut de révocation
        try {
            if (!revocationChecker.checkRevocationStatus(cert, issuerCert)) {
                isValid = false;
            }
        } catch (Exception e) {
            System.out.println("[X] Error checking revocation status: " + e.getMessage());
            // Nous n'invalidons pas le certificat si la vérification de révocation échoue
            // mais nous l'indiquons clairement
            System.out.println("  (Note: This is not considered critical for this validation)");
        }
        
        // 7. Vérification manuelle de la signature en fonction du type
        String sigType = CryptoUtils.getSignatureAlgorithmType(cert);
        System.out.println("=> Signature Algorithm Type: " + sigType);
        
        if (sigType.equals("RSA")) {
            if (!verifySignatureManuallyRSA(cert, keyToUse)) {
                System.out.println("[X] Error: Certificate signature could not be verified (manual RSA check).");
                isValid = false;
            } else {
                System.out.println("[OK] Certificate signature verified successfully (manual RSA check).");
            }
        } else if (sigType.equals("ECDSA")) {
            if (!verifySignatureManuallyECDSA(cert, keyToUse)) {
                System.out.println("[X] Error: Certificate signature could not be verified (manual ECDSA check).");
                isValid = false;
            } else {
                System.out.println("[OK] Certificate signature verified successfully (manual ECDSA check).");
            }
        } else {
            System.out.println(" Warning: Unknown signature algorithm type for manual verification: " + sigType);
        }
        
        return isValid;
    }
    
    /**
     * Vérifie la période de validité du certificat
     * 
     * @param cert Le certificat à vérifier
     * @return true si le certificat est valide pour la date actuelle, false sinon
     */
    public boolean verifyValidityPeriod(X509Certificate cert) {
        try {
            cert.checkValidity(new Date());
            return true;
        } catch (CertificateExpiredException e) {
            return false;
        } catch (CertificateNotYetValidException e) {
            return false;
        }
    }
    
    /**
     * Vérifie la signature d'un certificat avec une clé publique (méthode classique)
     * Utilise la méthode X509Certificate.verify()
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public boolean verifySignature(X509Certificate cert, PublicKey publicKey) {
        try {
            cert.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Vérifie la signature d'un certificat avec une clé publique (méthode avancée)
     * Utilise l'API java.security.Signature via CryptoUtils
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public boolean verifySignatureAdvanced(X509Certificate cert, PublicKey publicKey) {
        return CryptoUtils.verifySignatureAdvanced(cert, publicKey);
    }
    
    /**
     * Vérifie manuellement la signature RSA d'un certificat
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public boolean verifySignatureManuallyRSA(X509Certificate cert, PublicKey publicKey) {
        return CryptoUtils.verifyRSASignatureManually(cert, publicKey);
    }
    
    /**
     * Vérifie manuellement la signature ECDSA d'un certificat
     * 
     * @param cert Le certificat à vérifier
     * @param publicKey La clé publique à utiliser pour la vérification
     * @return true si la signature est valide, false sinon
     */
    public boolean verifySignatureManuallyECDSA(X509Certificate cert, PublicKey publicKey) {
        return CryptoUtils.verifyECDSASignatureManually(cert, publicKey);
    }
    
    /**
     * Vérifie l'extension KeyUsage du certificat
     * Vérification que l'extension est présente et que les bits digitalSignature et nonRepudiation sont activés
     * 
     * @param cert Le certificat à vérifier
     * @return true si l'extension KeyUsage est valide, false sinon
     */
    public boolean verifyKeyUsage(X509Certificate cert) {
        try {
            // Méthode 1: Utilisation de la méthode getKeyUsage de X509Certificate
            boolean[] keyUsage = cert.getKeyUsage();
            
            // Si l'extension n'est pas présente, considérer comme non valide
            if (keyUsage == null) {
                System.out.println("  KeyUsage extension not present");
                return false;
            }
            
            // Vérifier que les bits digitalSignature (0) et nonRepudiation (1) sont activés
            // Selon la RFC 5280, les bits sont définis comme suit:
            // 0: digitalSignature
            // 1: nonRepudiation (ou contentCommitment)
            boolean hasDigitalSignature = keyUsage.length > 0 && keyUsage[0];
            boolean hasNonRepudiation = keyUsage.length > 1 && keyUsage[1];
            
            if (!hasDigitalSignature) {
                System.out.println("  digitalSignature bit not set in KeyUsage");
            }
            
            if (!hasNonRepudiation) {
                System.out.println("  nonRepudiation bit not set in KeyUsage");
            }
            
            // Pour une validation complète, nous exigeons que les deux bits soient activés
            return hasDigitalSignature && hasNonRepudiation;
            
        } catch (Exception e) {
            System.out.println("Error verifying KeyUsage extension: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Vérifie l'extension BasicConstraints du certificat
     * Cette extension indique si un certificat peut émettre d'autres certificats (CA)
     * 
     * @param cert Le certificat à vérifier
     * @param isCA Indique si le certificat est censé être une autorité de certification
     * @return true si l'extension BasicConstraints est valide, false sinon
     */
    public boolean verifyBasicConstraints(X509Certificate cert, boolean isCA) {
        try {
            // Extraction de l'extension BasicConstraints avec BouncyCastle
            BasicConstraints basicConstraints = extractBasicConstraintsExtension(cert);
            
            // Si l'extension n'est pas présente
            if (basicConstraints == null) {
                System.out.println("  BasicConstraints extension not present");
                // Pour un certificat d'autorité, c'est une erreur
                if (isCA) {
                    return false;
                }
                // Pour un certificat feuille, on peut accepter l'absence (mais c'est une mauvaise pratique)
                return true;
            }
            
            // Vérifier si le certificat est marqué comme CA
            boolean isCertCA = basicConstraints.isCA();
            
            // Si le certificat est censé être une CA mais n'est pas marqué comme tel
            if (isCA && !isCertCA) {
                System.out.println("  Certificate should be a CA but is not marked as such");
                return false;
            }
            
            // Si le certificat n'est pas censé être une CA mais est marqué comme tel
            if (!isCA && isCertCA) {
                System.out.println("  Certificate is not expected to be a CA but is marked as such");
                // Ce n'est pas une erreur critique pour notre validation (juste une anomalie)
                return true;
            }
            
            // Vérifier la limite de la chaîne pour les CA (pathLenConstraint)
            if (isCertCA) {
                int pathLen = basicConstraints.getPathLenConstraint() != null ? 
                        basicConstraints.getPathLenConstraint().intValue() : -1;
                if (pathLen >= 0) {
                    System.out.println("  CA certificate with path length constraint: " + pathLen);
                } else {
                    System.out.println("  CA certificate with no path length constraint");
                }
            }
            
            return true;
            
        } catch (Exception e) {
            System.out.println("Error verifying BasicConstraints extension: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Extrait l'extension BasicConstraints d'un certificat avec BouncyCastle
     * 
     * @param cert Le certificat à analyser
     * @return L'objet BasicConstraints ou null si l'extension n'est pas présente
     */
    private BasicConstraints extractBasicConstraintsExtension(X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue(Extension.basicConstraints.getId());
            if (extensionValue == null) {
                return null;
            }
            
            ASN1InputStream asn1Stream = new ASN1InputStream(new ByteArrayInputStream(extensionValue));
            DEROctetString derOctetString = (DEROctetString) asn1Stream.readObject();
            asn1Stream.close();
            
            byte[] octets = derOctetString.getOctets();
            asn1Stream = new ASN1InputStream(new ByteArrayInputStream(octets));
            ASN1Primitive derObject = asn1Stream.readObject();
            asn1Stream.close();
            
            return BasicConstraints.getInstance(derObject);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Méthode alternative pour extraire l'extension KeyUsage avec BouncyCastle
     * Utilisée pour une analyse plus détaillée si nécessaire
     * 
     * @param cert Le certificat à vérifier
     * @return L'objet KeyUsage ou null si l'extension n'est pas présente
     */
    private KeyUsage extractKeyUsageExtension(X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue(Extension.keyUsage.getId());
            if (extensionValue == null) {
                return null;
            }
            
            ASN1InputStream asn1Stream = new ASN1InputStream(new ByteArrayInputStream(extensionValue));
            DEROctetString derOctetString = (DEROctetString) asn1Stream.readObject();
            asn1Stream.close();
            
            byte[] octets = derOctetString.getOctets();
            asn1Stream = new ASN1InputStream(new ByteArrayInputStream(octets));
            ASN1Primitive derObject = asn1Stream.readObject();
            asn1Stream.close();
            
            return KeyUsage.getInstance(derObject);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Vérifie si un certificat est auto-signé
     * 
     * @param cert Le certificat à vérifier
     * @return true si le certificat est auto-signé, false sinon
     */
    public boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }
}