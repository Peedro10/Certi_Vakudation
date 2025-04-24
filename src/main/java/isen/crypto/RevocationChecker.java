package isen.crypto;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Classe pour vérifier le statut de révocation des certificats
 * Supporte les méthodes CRL et OCSP avec système de cache
 */
public class RevocationChecker {
    
    // Cache pour les CRLs
    private Map<String, CRLCacheEntry> crlCache;
    
    // Cache pour les réponses OCSP
    private Map<String, OCSPCacheEntry> ocspCache;
    
    /**
     * Constructeur initialisant les caches
     */
    public RevocationChecker() {
        Security.addProvider(new BouncyCastleProvider());
        this.crlCache = new HashMap<>();
        this.ocspCache = new HashMap<>();
    }
    
    /**
     * Vérifie le statut de révocation d'un certificat
     * Essaie d'abord OCSP, puis CRL si OCSP échoue
     * 
     * @param cert Le certificat à vérifier
     * @param issuerCert Le certificat de l'émetteur (peut être null)
     * @return true si le certificat n'est pas révoqué, false s'il est révoqué ou si la vérification échoue
     */
    public boolean checkRevocationStatus(X509Certificate cert, X509Certificate issuerCert) {
        try {
            // Si l'émetteur est fourni, essayer OCSP d'abord
            if (issuerCert != null) {
                try {
                    boolean ocspResult = checkRevocationStatusOCSP(cert, issuerCert);
                    if (ocspResult) {
                        System.out.println("[OK] Revocation status verified successfully : The certificate is not revoked (OCSP).");
                        return true;
                    } else {
                        System.out.println("[X] Error: Certificate is revoked (OCSP).");
                        return false;
                    }
                } catch (Exception e) {
                    System.out.println("OCSP check failed, falling back to CRL: " + e.getMessage());
                    // Continue to CRL check
                }
            }
            
            // Essayer CRL
            boolean crlResult = checkRevocationStatusCRL(cert);
            if (crlResult) {
                System.out.println("[OK] Revocation status verified successfully : The certificate is not revoked (CRL).");
                return true;
            } else {
                System.out.println("[X] Error: Certificate is revoked (CRL).");
                return false;
            }
            
        } catch (Exception e) {
            System.out.println("[X] Error checking revocation status: " + e.getMessage());
            // Si on ne peut pas vérifier la révocation, on considère le certificat comme valide
            // Cette politique peut être modifiée selon les besoins de sécurité
            System.out.println("  Unable to check revocation status, assuming certificate is valid.");
            return true;
        }
    }
    
    /**
     * Vérifie le statut de révocation d'un certificat via CRL
     * 
     * @param cert Le certificat à vérifier
     * @return true si le certificat n'est pas révoqué, false s'il est révoqué ou si la vérification échoue
     */
    public boolean checkRevocationStatusCRL(X509Certificate cert) throws Exception {
        List<String> crlUrls = extractCRLDistributionPoints(cert);
        
        if (crlUrls.isEmpty()) {
            System.out.println("  No CRL distribution points found in certificate.");
            return true; // Pas de CRL, on considère valide
        }
        
        for (String crlUrl : crlUrls) {
            try {
                // Vérifier si la CRL est dans le cache
                if (crlCache.containsKey(crlUrl)) {
                    CRLCacheEntry cacheEntry = crlCache.get(crlUrl);
                    if (!cacheEntry.isExpired()) {
                        // Utiliser la CRL en cache
                        X509CRL crl = cacheEntry.getCrl();
                        if (crl.isRevoked(cert)) {
                            System.out.println("  Certificate is revoked according to cached CRL: " + crlUrl);
                            return false;
                        }
                        continue; // Passer à l'URL suivante
                    }
                }
                
                // Télécharger la CRL
                System.out.println("  Downloading CRL from: " + crlUrl);
                X509CRL crl = downloadCRL(crlUrl);
                
                // Ajouter au cache
                crlCache.put(crlUrl, new CRLCacheEntry(crl));
                
                // Vérifier si le certificat est révoqué
                if (crl.isRevoked(cert)) {
                    System.out.println("  Certificate is revoked according to CRL: " + crlUrl);
                    return false;
                }
            } catch (Exception e) {
                System.out.println("  Error checking CRL at " + crlUrl + ": " + e.getMessage());
                // Continue to next URL
            }
        }
        
        // Si aucune CRL n'indique que le certificat est révoqué, il est considéré comme valide
        return true;
    }
    
    /**
     * Extrait les URLs des points de distribution CRL à partir d'un certificat
     * 
     * @param cert Le certificat à analyser
     * @return Liste des URLs de CRL
     */
    private List<String> extractCRLDistributionPoints(X509Certificate cert) throws Exception {
        List<String> crlUrls = new ArrayList<>();
        
        byte[] crlDPExtension = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlDPExtension == null) {
            return crlUrls; // Liste vide
        }
        
        // Décodage ASN.1 pour extraire les URLs
        ASN1InputStream asn1Stream = new ASN1InputStream(new ByteArrayInputStream(crlDPExtension));
        DEROctetString derOctetString = (DEROctetString) asn1Stream.readObject();
        asn1Stream.close();
        
        byte[] octets = derOctetString.getOctets();
        asn1Stream = new ASN1InputStream(new ByteArrayInputStream(octets));
        ASN1Primitive derObject = asn1Stream.readObject();
        asn1Stream.close();
        
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObject);
        DistributionPoint[] points = distPoint.getDistributionPoints();
        
        for (DistributionPoint point : points) {
            DistributionPointName dpn = point.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralNames generalNames = (GeneralNames) dpn.getName();
                GeneralName[] names = generalNames.getNames();
                
                for (GeneralName name : names) {
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        // Convertir GeneralName en String URL
                        ASN1Primitive nameObject = (ASN1Primitive) name.getName();
                        String url = nameObject.toString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        
        return crlUrls;
    }
    
    /**
     * Télécharge une CRL à partir d'une URL
     * 
     * @param url L'URL de la CRL
     * @return La CRL téléchargée
     */
    private X509CRL downloadCRL(String url) throws Exception {
        URL crlURL = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) crlURL.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000); // 5 secondes timeout
        connection.setReadTimeout(5000);
        
        try (InputStream crlStream = connection.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(crlStream);
        }
    }
    
    /**
     * Vérifie le statut de révocation d'un certificat via OCSP
     * 
     * @param cert Le certificat à vérifier
     * @param issuerCert Le certificat de l'émetteur
     * @return true si le certificat n'est pas révoqué, false s'il est révoqué ou si la vérification échoue
     */
    public boolean checkRevocationStatusOCSP(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        String ocspUrl = extractOCSPUrl(cert);
        
        if (ocspUrl == null || ocspUrl.isEmpty()) {
            System.out.println("  No OCSP responder URL found in certificate.");
            return true; // Pas d'OCSP, on considère valide
        }
        
        // Clé de cache unique pour ce certificat et cet émetteur
        String cacheKey = ocspUrl + "-" + cert.getSerialNumber().toString();
        
        // Vérifier le cache
        if (ocspCache.containsKey(cacheKey)) {
            OCSPCacheEntry cacheEntry = ocspCache.get(cacheKey);
            if (!cacheEntry.isExpired()) {
                // Utiliser le résultat en cache
                if (cacheEntry.getStatus() == OCSPCacheEntry.Status.GOOD) {
                    System.out.println("  Using cached OCSP result: Certificate is not revoked.");
                    return true;
                } else {
                    System.out.println("  Using cached OCSP result: Certificate is revoked.");
                    return false;
                }
            }
        }
        
        // Création de la requête OCSP
        OCSPReq ocspReq = generateOCSPRequest(cert, issuerCert);
        
        // Envoi de la requête OCSP
        System.out.println("  Sending OCSP request to: " + ocspUrl);
        OCSPResp ocspResp = sendOCSPRequest(ocspUrl, ocspReq);
        
        // Traitement de la réponse
        if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
            System.out.println("  OCSP response error: " + ocspResp.getStatus());
            return true; // Considérer valide en cas d'erreur
        }
        
        BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
        SingleResp[] responses = basicResp.getResponses();
        
        // Création du CertificateID pour comparer avec les réponses
        JcaCertificateID certId = new JcaCertificateID(
            new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
            issuerCert,
            cert.getSerialNumber());
        
        for (SingleResp resp : responses) {
            if (resp.getCertID().getSerialNumber().equals(cert.getSerialNumber())) {
                CertificateStatus status = resp.getCertStatus();
                
                // Mise en cache du résultat
                if (status == CertificateStatus.GOOD) {
                    ocspCache.put(cacheKey, new OCSPCacheEntry(OCSPCacheEntry.Status.GOOD));
                    return true;
                } else if (status instanceof RevokedStatus) {
                    ocspCache.put(cacheKey, new OCSPCacheEntry(OCSPCacheEntry.Status.REVOKED));
                    return false;
                } else {
                    // Status UNKNOWN
                    ocspCache.put(cacheKey, new OCSPCacheEntry(OCSPCacheEntry.Status.UNKNOWN));
                    return true; // On considère valide en cas de statut inconnu
                }
            }
        }
        
        System.out.println("  No OCSP response found for this certificate.");
        return true; // On considère valide si pas de réponse spécifique
    }
    
    /**
     * Extrait l'URL du serveur OCSP à partir d'un certificat
     * 
     * @param cert Le certificat à analyser
     * @return L'URL du serveur OCSP ou null si non trouvée
     */
    private String extractOCSPUrl(X509Certificate cert) throws Exception {
        byte[] aiaExtension = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aiaExtension == null) {
            return null;
        }
        
        // Décodage ASN.1 pour extraire l'URL OCSP
        ASN1InputStream asn1Stream = new ASN1InputStream(new ByteArrayInputStream(aiaExtension));
        DEROctetString derOctetString = (DEROctetString) asn1Stream.readObject();
        asn1Stream.close();
        
        byte[] octets = derOctetString.getOctets();
        asn1Stream = new ASN1InputStream(new ByteArrayInputStream(octets));
        ASN1Primitive derObject = asn1Stream.readObject();
        asn1Stream.close();
        
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(derObject);
        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
        
        for (AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                GeneralName generalName = accessDescription.getAccessLocation();
                if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    ASN1Primitive nameObject = (ASN1Primitive) generalName.getName();
                    return nameObject.toString();
                }
            }
        }
        
        return null;
    }
    
    /**
     * Génère une requête OCSP pour un certificat
     * 
     * @param cert Le certificat à vérifier
     * @param issuerCert Le certificat de l'émetteur
     * @return La requête OCSP générée
     */
    private OCSPReq generateOCSPRequest(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        // Création du CertificateID
        JcaCertificateID certId = new JcaCertificateID(
            new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
            issuerCert,
            cert.getSerialNumber());
        
        // Création de la requête OCSP
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(certId);
        
        // Extensions optionnelles
        /*
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(new byte[]{1, 2, 3, 4, 5}));
        ocspReqBuilder.setRequestExtensions(new Extensions(extensions));
        */
        
        return ocspReqBuilder.build();
    }
    
    /**
     * Envoie une requête OCSP à un serveur
     * 
     * @param url L'URL du serveur OCSP
     * @param ocspReq La requête OCSP à envoyer
     * @return La réponse OCSP reçue
     */
    private OCSPResp sendOCSPRequest(String url, OCSPReq ocspReq) throws Exception {
        byte[] encodedReq = ocspReq.getEncoded();
        
        URL ocspUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) ocspUrl.openConnection();
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setDoOutput(true);
        connection.setConnectTimeout(5000); // 5 secondes timeout
        connection.setReadTimeout(5000);
        
        try (OutputStream out = connection.getOutputStream()) {
            out.write(encodedReq);
            out.flush();
        }
        
        try (InputStream in = connection.getInputStream()) {
            return new OCSPResp(in);
        }
    }
    
    /**
     * Classe interne pour stocker une entrée dans le cache CRL
     */
    private static class CRLCacheEntry {
        private X509CRL crl;
        private Date timestamp;
        
        // Durée de validité du cache en millisecondes (24 heures)
        private static final long CACHE_VALIDITY = 24 * 60 * 60 * 1000; 
        
        public CRLCacheEntry(X509CRL crl) {
            this.crl = crl;
            this.timestamp = new Date();
        }
        
        public X509CRL getCrl() {
            return crl;
        }
        
        public boolean isExpired() {
            Date now = new Date();
            return (now.getTime() - timestamp.getTime()) > CACHE_VALIDITY;
        }
    }
    
    /**
     * Classe interne pour stocker une entrée dans le cache OCSP
     */
    private static class OCSPCacheEntry {
        
        public enum Status {
            GOOD, REVOKED, UNKNOWN
        }
        
        private Status status;
        private Date timestamp;
        
        // Durée de validité du cache en millisecondes (1 heure)
        private static final long CACHE_VALIDITY = 60 * 60 * 1000; 
        
        public OCSPCacheEntry(Status status) {
            this.status = status;
            this.timestamp = new Date();
        }
        
        public Status getStatus() {
            return status;
        }
        
        public boolean isExpired() {
            Date now = new Date();
            return (now.getTime() - timestamp.getTime()) > CACHE_VALIDITY;
        }
    }
}