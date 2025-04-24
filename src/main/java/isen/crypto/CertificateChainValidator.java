package isen.crypto;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;

/**
 * Classe pour valider une chaîne de certificats X.509
 * Vérifie la hiérarchie complète des certificats du certificat feuille jusqu'au certificat racine
 */
public class CertificateChainValidator {
    
    // Instance du validateur de certificat individuel
    private CertificateValidator certificateValidator;
    
    /**
     * Constructeur
     */
    public CertificateChainValidator() {
        this.certificateValidator = new CertificateValidator();
    }
    
    /**
     * Valide une chaîne de certificats
     * @param chain La liste des certificats dans la chaîne (du certificat feuille au certificat racine)
     * @return true si la chaîne est valide, false sinon
     */
    public boolean validateChain(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) {
            System.out.println("Chain validation failed: Empty or null chain");
            return false;
        }
        
        System.out.println("\n===== VALIDATION DE LA CHAÎNE DE CERTIFICATS =====");
        System.out.println("Nombre de certificats dans la chaîne: " + chain.size());
        System.out.println();
        
        // Vérifier chaque certificat individuellement
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            X509Certificate issuer = (i < chain.size() - 1) ? chain.get(i + 1) : null;
            
            System.out.println("=== Certificat #" + (i + 1) + " ===");
            System.out.println("Sujet: " + cert.getSubjectX500Principal().getName());
            System.out.println("Émetteur: " + cert.getIssuerX500Principal().getName());
            
            // Détecter le type de certificat
            String certType;
            if (i == 0) {
                certType = "Certificat feuille (End-entity)";
            } else if (i == chain.size() - 1 && certificateValidator.isSelfSigned(cert)) {
                certType = "Certificat racine (Root CA)";
            } else {
                certType = "Certificat intermédiaire (Intermediate CA)";
            }
            System.out.println("Type: " + certType);
            
            // Vérifier que chaque certificat est valide
            if (!validateSingleCertificate(cert, issuer, i == chain.size() - 1)) {
                System.out.println("[X] Échec de la validation du certificat #" + (i + 1));
                return false;
            }
            
            // Vérifier que le certificat actuel est bien émis par le suivant (sauf pour le dernier)
            if (issuer != null && !verifyIssuedBy(cert, issuer)) {
                System.out.println("[X] Erreur: Le certificat #" + (i + 1) + " n'est pas émis par le certificat #" + (i + 2));
                return false;
            }
            
            System.out.println();
        }
        
        // Vérifier l'ordre des certificats dans la chaîne
        if (!validateChainOrder(chain)) {
            System.out.println("[X] Erreur: La chaîne de certificats n'est pas dans le bon ordre");
            return false;
        }
        
        // Vérifier les contraintes de longueur de chaîne (pathLenConstraint)
        if (!validatePathLengthConstraints(chain)) {
            System.out.println("[X] Erreur: Les contraintes de longueur de chaîne ne sont pas respectées");
            return false;
        }
        
        System.out.println("===== RÉSULTAT DE LA VALIDATION DE LA CHAÎNE =====");
        System.out.println("[OK] La chaîne de certificats est valide.");
        return true;
    }
    
    /**
     * Valide un certificat individuel dans le contexte de la chaîne
     * @param cert Le certificat à valider
     * @param issuer Le certificat émetteur (null si c'est un certificat auto-signé)
     * @param isRoot true si c'est le certificat racine
     * @return true si le certificat est valide, false sinon
     */
    private boolean validateSingleCertificate(X509Certificate cert, X509Certificate issuer, boolean isRoot) {
        try {
            // Vérifier la période de validité
            cert.checkValidity(new Date());
            System.out.println("  [OK] Période de validité : " + 
                CertificateUtils.extractFileName(cert.getNotBefore().toString()) + " - " + 
                CertificateUtils.extractFileName(cert.getNotAfter().toString()));
            
            // Vérifier la signature
            PublicKey keyToVerify = (issuer != null) ? issuer.getPublicKey() : cert.getPublicKey();
            cert.verify(keyToVerify);
            System.out.println("  [OK] Signature valide");
            
            // Vérifier les extensions basiques
            if (isRoot) {
                // Pour un certificat racine, vérifier qu'il est auto-signé
                if (!certificateValidator.isSelfSigned(cert)) {
                    System.out.println("  [X] Erreur: Le certificat racine n'est pas auto-signé");
                    return false;
                }
                System.out.println("  [OK] Certificat racine auto-signé");
            }
            
            // Vérifier les contraintes pour les CA
            if (cert.getBasicConstraints() != -1) {
                // C'est un certificat CA
                if (!certificateValidator.verifyBasicConstraints(cert, true)) {
                    System.out.println("  [X] Erreur: BasicConstraints invalides pour un certificat CA");
                    return false;
                }
                System.out.println("  [OK] BasicConstraints valides pour CA");
            } else if (isRoot || (issuer != null && certificateValidator.isSelfSigned(issuer))) {
                // Un certificat racine ou un certificat intermédiaire doit être CA
                System.out.println("  [X] Erreur: Ce certificat devrait être CA mais ne l'est pas");
                return false;
            }
            
            return true;
            
        } catch (CertificateExpiredException e) {
            System.out.println("  [X] Erreur: Certificat expiré");
        } catch (CertificateNotYetValidException e) {
            System.out.println("  [X] Erreur: Certificat pas encore valide");
        } catch (Exception e) {
            System.out.println("  [X] Erreur de validation: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Vérifie qu'un certificat est bien émis par un autre
     * @param cert Le certificat à vérifier
     * @param issuer Le certificat émetteur supposé
     * @return true si cert est émis par issuer, false sinon
     */
    private boolean verifyIssuedBy(X509Certificate cert, X509Certificate issuer) {
        try {
            // Vérifier que le DN de l'émetteur correspond
            if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return false;
            }
            
            // Vérifier la signature
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Vérifie que la chaîne est dans le bon ordre (du certificat feuille au racine)
     * @param chain La chaîne de certificats
     * @return true si l'ordre est correct, false sinon
     */
    private boolean validateChainOrder(List<X509Certificate> chain) {
        // Le premier certificat devrait être le certificat feuille (non CA ou CA avec contraintes)
        X509Certificate firstCert = chain.get(0);
        if (firstCert.getBasicConstraints() != -1 && firstCert.getBasicConstraints() > chain.size() - 2) {
            return false;
        }
        
        // Le dernier certificat devrait être auto-signé (certificat racine)
        X509Certificate lastCert = chain.get(chain.size() - 1);
        if (!certificateValidator.isSelfSigned(lastCert)) {
            return false;
        }
        
        // Chaque certificat devrait être émis par le suivant dans la chaîne
        for (int i = 0; i < chain.size() - 1; i++) {
            if (!verifyIssuedBy(chain.get(i), chain.get(i + 1))) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Vérifie les contraintes de longueur de chemin (pathLenConstraint)
     * @param chain La chaîne de certificats
     * @return true si les contraintes sont respectées, false sinon
     */
    private boolean validatePathLengthConstraints(List<X509Certificate> chain) {
        int pathLen = 0;
        
        // Parcourir la chaîne de la fin vers le début (du certificat racine vers le feuille)
        for (int i = chain.size() - 1; i > 0; i--) {
            X509Certificate cert = chain.get(i);
            int basicConstraints = cert.getBasicConstraints();
            
            if (basicConstraints != -1) {
                // C'est un certificat CA
                if (basicConstraints < pathLen) {
                    System.out.println("  [X] Contrainte pathLen violée pour le certificat: " + 
                        cert.getSubjectX500Principal().getName());
                    return false;
                }
                pathLen++;
            }
        }
        
        return true;
    }
    
    /**
     * Valide une chaîne complète en incluant la vérification de révocation
     * @param chain La chaîne de certificats
     * @param checkRevocation true pour vérifier le statut de révocation
     * @return true si la chaîne est valide, false sinon
     */
    public boolean validateChainWithRevocation(List<X509Certificate> chain, boolean checkRevocation) {
        if (!validateChain(chain)) {
            return false;
        }
        
        if (checkRevocation) {
            System.out.println("\n===== VÉRIFICATION DE RÉVOCATION DE LA CHAÎNE =====");
            RevocationChecker revocationChecker = new RevocationChecker();
            
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate cert = chain.get(i);
                X509Certificate issuer = (i < chain.size() - 1) ? chain.get(i + 1) : null;
                
                System.out.println("Vérification de révocation du certificat #" + (i + 1));
                if (!revocationChecker.checkRevocationStatus(cert, issuer)) {
                    System.out.println("[X] Certificat révoqué dans la chaîne");
                    return false;
                }
            }
            
            System.out.println("[OK] Aucun certificat révoqué dans la chaîne");
        }
        
        return true;
    }
}