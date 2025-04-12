package isen.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;

/**
 * Classe utilitaire pour l'extraction d'informations des certificats X.509.
 */
public class CertificateUtils {

    /**
     * Charge un certificat X.509 à partir d'un fichier au format DER ou PEM.
     */
    public static X509Certificate loadCertificate(String format, String path) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in;

        if (format.equalsIgnoreCase("DER")) {
            in = new FileInputStream(path);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            in.close();
            return cert;
        } else if (format.equalsIgnoreCase("PEM")) {
            String content = Files.readString(new File(path).toPath());
            content = content.replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(content);
            in = new java.io.ByteArrayInputStream(decoded);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            in.close();
            return cert;
        } else {
            throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    /**
     * Extrait les URLs de distribution CRL (Certificate Revocation List) du certificat.
     */
    public static List<String> getCRLDistributionPoints(X509Certificate cert) throws Exception {
        byte[] crlExtension = cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId());
        if (crlExtension == null) return List.of();

        List<String> crlUrls = new ArrayList<>();

        try (ASN1InputStream in = new ASN1InputStream(crlExtension)) {
            ASN1OctetString octetString = (ASN1OctetString) in.readObject();
            try (ASN1InputStream seqIn = new ASN1InputStream(octetString.getOctets())) {
                ASN1Sequence dpSeq = (ASN1Sequence) seqIn.readObject();

                for (int i = 0; i < dpSeq.size(); i++) {
                    DistributionPoint dp = DistributionPoint.getInstance(dpSeq.getObjectAt(i));
                    DistributionPointName dpName = dp.getDistributionPoint();

                    if (dpName != null && dpName.getType() == DistributionPointName.FULL_NAME) {
                        GeneralNames gns = GeneralNames.getInstance(dpName.getName());
                        for (GeneralName gn : gns.getNames()) {
                            if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String url = gn.getName().toString();
                                crlUrls.add(url);
                            }
                        }
                    }
                }
            }
        }

        return crlUrls;
    }

    /**
     * Extrait l'URL OCSP à partir de l'extension AuthorityInfoAccess du certificat.
     */
    public static URI getOCSPUrl(X509Certificate cert) throws Exception {
        byte[] aiaExtension = cert.getExtensionValue("1.3.6.1.5.5.7.1.1"); // OID de AuthorityInfoAccess
        if (aiaExtension == null) return null;

        try (ASN1InputStream in = new ASN1InputStream(aiaExtension)) {
            ASN1OctetString octets = (ASN1OctetString) in.readObject();
            try (ASN1InputStream seqIn = new ASN1InputStream(octets.getOctets())) {
                ASN1Sequence seq = (ASN1Sequence) seqIn.readObject();

                for (int i = 0; i < seq.size(); i++) {
                    AccessDescription desc = AccessDescription.getInstance(seq.getObjectAt(i));

                    if (desc.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                        GeneralName gn = desc.getAccessLocation();
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            return new URI(gn.getName().toString());
                        }
                    }
                }
            }
        }

        return null;
    }
}