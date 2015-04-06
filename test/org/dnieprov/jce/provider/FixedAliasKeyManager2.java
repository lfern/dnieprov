/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import javax.net.ssl.X509KeyManager;

/**
 *
 * @author luis
 */
public class FixedAliasKeyManager2 extends FixedAliasKeyManager{
    KeyStore ks;
    public FixedAliasKeyManager2(X509KeyManager keyManager, String alias,KeyStore ks) {
        super(keyManager, alias);
        this.ks = ks;
    }
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] c = super.getCertificateChain(alias);
        if (c == null || c.length != 1){
            return c;
        }
        try {
            PKIXParameters params = new PKIXParameters(ks);
            
            X509Certificate toFind = c[0];
            ArrayList<X509Certificate> l = new ArrayList<X509Certificate>();
            l.add(toFind);
            while (true){
                TrustAnchor trust = CertUtil.findTrustAnchor(toFind, params.getTrustAnchors());
                X509Certificate cert = trust.getTrustedCert();
                if (cert.equals(toFind)) break;
                l.add(cert);
                toFind = cert;
            }
            return  l.toArray(new X509Certificate[0]);
            
        } catch (CertPathBuilderException ex){
            ex.printStackTrace();
        } catch (InvalidAlgorithmParameterException ex){
            ex.printStackTrace();
        } catch (KeyStoreException ex){
            ex.printStackTrace();
        }
        return c;
    }
}
