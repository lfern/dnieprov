/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.dnieprov.jce.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;

/**
 *
 * @author luis
 */
public class FixedAliasKeyManager implements X509KeyManager {

    private final X509KeyManager keyManager;
    private final String alias;

    /**
     * Creates a new instance from an existing X509KeyManager.
     *
     * @param keyManager X509KeyManager to wrap.
     * @param alias alias to use to choose a key for the server sockets.
     */
    public FixedAliasKeyManager(X509KeyManager keyManager, String alias) {
        this.keyManager = keyManager;
        this.alias = alias;
    }

    /**
     * Relays the call to the wrapped X509KeyManager.
     *
     * @see javax.net.ssl.X509KeyManager#chooseClientAlias(java.lang.String[],
     * java.security.Principal[], java.net.Socket)
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers,
            Socket socket) {
        //return this.keyManager.chooseClientAlias(keyType, issuers, socket);
        return this.alias;
    }

    /**
     * Returns the alias this instance has been constructed with, regardless of
     * any other parameters.
     *
     * @return The alias passed to the constructor.
     * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String,
     * java.security.Principal[], java.net.Socket)
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers,
            Socket socket) {
        return this.alias;
    }

    /**
     * Relays the call to the wrapped X509KeyManager.
     *
     * @see javax.net.ssl.X509KeyManager#getCertificateChain(java.lang.String)
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return this.keyManager.getCertificateChain(alias);
    }

    /**
     * Relays the call to the wrapped X509KeyManager.
     *
     * @see javax.net.ssl.X509KeyManager#getClientAliases(java.lang.String,
     * java.security.Principal[])
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.keyManager.getClientAliases(keyType, issuers);
    }

    /**
     * Relays the call to the wrapped X509KeyManager.
     *
     * @see javax.net.ssl.X509KeyManager#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        PrivateKey k = this.keyManager.getPrivateKey(alias);
        return k;
    }

    /**
     * Relays the call to the wrapped X509KeyManager.
     *
     * @see javax.net.ssl.X509KeyManager#getServerAliases(java.lang.String,
     * java.security.Principal[])
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.keyManager.getServerAliases(keyType, issuers);
    }
}
