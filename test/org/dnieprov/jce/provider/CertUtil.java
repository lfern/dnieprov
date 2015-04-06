/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.jce.provider;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilderException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/**
 *
 * @author luis
 */
public class CertUtil {

    public static TrustAnchor findTrustAnchor(
            X509Certificate cert,
            Set trustAnchors)
            throws CertPathBuilderException {
        Iterator iter = trustAnchors.iterator();
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;

        X509CertSelector certSelectX509 = new X509CertSelector();

        try {
            certSelectX509.setSubject(cert.getIssuerX500Principal().getEncoded());
        } catch (IOException ex) {
            throw new CertPathBuilderException("can't get trust anchor principal", null);
        }

        while (iter.hasNext() && trust == null) {
            trust = (TrustAnchor) iter.next();
            if (trust.getTrustedCert() != null) {
                if (certSelectX509.match(trust.getTrustedCert())) {
                    trustPublicKey = trust.getTrustedCert().getPublicKey();
                } else {
                    trust = null;
                }
            } else if (trust.getCAName() != null
                    && trust.getCAPublicKey() != null) {
                try {
                    X500Principal certIssuer = cert.getIssuerX500Principal();
                    X500Principal caName = new X500Principal(trust.getCAName());
                    if (certIssuer.equals(caName)) {
                        trustPublicKey = trust.getCAPublicKey();
                    } else {
                        trust = null;
                    }
                } catch (IllegalArgumentException ex) {
                    trust = null;
                }
            } else {
                trust = null;
            }

            if (trustPublicKey != null) {
                try {
                    cert.verify(trustPublicKey);
                } catch (Exception ex) {
                    invalidKeyEx = ex;
                    trust = null;
                }
            }
        }

        if (trust == null && invalidKeyEx != null) {
            throw new CertPathBuilderException("TrustAnchor found put certificate validation failed", invalidKeyEx);
        }

        return trust;
    }
}
