/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.jce.provider;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 *
 * @author luis
 */
public class AllTrustManager implements X509TrustManager {

    private final X509TrustManager tm;
    private X509Certificate[] chain;

    AllTrustManager(X509TrustManager tm) {
        this.tm = tm;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        /*
         return new X509Certificate[]{
         this.chain[1]
         };
         */
        return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        for (int i = 0; i < chain.length; i++) {
            //System.out.println(chain[i].toString());
        }
        this.chain = chain;
        //tm.checkServerTrusted(chain, authType);
    }
}
