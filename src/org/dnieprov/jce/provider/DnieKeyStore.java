/**
 * Dnieprov es una librería que implementa un driver en JAVA para el DNI 
 * electrónico y un proveedor cryptográfico compatible con la JCA de Java.
 * Código fuente disponible en http://github.com/lfern/dnieprov
 * 
 * Copyright 2012 Luis Fernando Pardo Fincias
 * 
 * Este fichero se distribuye bajo una licencia dúal: LGPL 3.0 y EUPL 1.1:  
 * - GNU Lesser General Public License (LGPL), version 3.0
 * - European Union Public Licence (EUPL), version 1.1
 * ----------------------------------------------------------------------
 * Si se decide por la licencia LGPL, se aplica el siguiente aviso:
 * 
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License
 *   as published by the Free Software Foundation, either version 3
 *   of the License, or (at your option) any later version.   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.  
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see http://www.gnu.org/licenses/
 * 
 * ----------------------------------------------------------------------* 
 * Si se decide por la licencia EUPL se aplica este otro:
 * 
 *   Licencia con arreglo a la EUPL, Versión 1.1 exclusivamente (la "Licencia");
 *   Solo podrá usarse esta obra si se respeta la Licencia.
 *   Puede obtenerse una copia de la Licencia en:
 *   http://ec.europa.eu/idabc/eupl.html 
 *   El programa distribuido con arreglo a la Licencia se distribuye "TAL CUAL",
 *   SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * ----------------------------------------------------------------------* 
 */
package org.dnieprov.jce.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import org.dnieprov.driver.DnieCard;
import org.dnieprov.driver.DnieDriver;
import org.dnieprov.driver.DniePrivateKey;
import org.dnieprov.driver.DnieSession;
import org.dnieprov.driver.exceptions.DnieDriverException;
import org.dnieprov.driver.exceptions.DnieDriverPinException;
import org.dnieprov.driver.exceptions.InvalidCardException;

/**
 * Implementation of key store engine for DNIe.
 * @author luis
 * 
 */
public final class DnieKeyStore extends KeyStoreSpi {
    
    private final DnieDriver driver;
    //private Hashtable<DnieCard,DnieSession> currentCards = new Hashtable();
    private ConcurrentHashMap <DnieCard,DnieSession> currentCards = new ConcurrentHashMap();
    
    static final int NULL           = 0;
    static final int CERTIFICATE    = 1;
    static final int KEY            = 2;
    
    static final String KEY_ALIAS_PREFIX = "KEY-";
    
    public DnieKeyStore(DnieDriver driver){
        this.driver = driver;
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            String subject = alias;
            if (subject.startsWith(KEY_ALIAS_PREFIX)){
                subject = subject.substring(KEY_ALIAS_PREFIX.length());
            }
            updateCards();
            DnieSession session = getDnieSession4SubjectDN(subject);
            if (session != null){
                Enumeration<Key> keys = driver.getKeys(session);
                while(keys.hasMoreElements()){
                    DniePrivateKey key = (DniePrivateKey) keys.nextElement();
                    if (subject.equals(key.getCertificate().getSubjectDN().toString())){
                        return key;
                    }
                }
            }
            
        } catch (DnieDriverException ex){
            /** TODO: try to establish new session: card insertion/removal */
        } catch (DnieDriverPinException ex){
            /** TODO: try to establish new session: card insertion/removal */
        } catch (InvalidCardException ex){
            /** card removal do nothing */
        }
        return null;
        
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Certificate cert = engineGetCertificate(alias);
        if (cert == null){
            return null;
        }
        Certificate [] certArray = new Certificate[1];
        certArray[0] = cert;
        return certArray;
        
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            updateCards();
            DnieSession session = getDnieSession4SubjectDN(alias);
            if (session != null){
                Enumeration<X509Certificate> certs = driver.getCerts(session);
                while(certs.hasMoreElements()){
                    X509Certificate cert = certs.nextElement();
                    if (alias.equals(cert.getSubjectDN().toString())){
                        return cert;
                    }
                }
            }
        } catch (DnieDriverException ex){
            
        } catch (DnieDriverPinException ex){
            
        } catch (InvalidCardException ex){
            
        }
        
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }


    @Override
    public Enumeration<String> engineAliases() {
        updateCards();
        Iterator<DnieCard> iterator = currentCards.keySet().iterator();
        ArrayList<String> list = new ArrayList();
        
        while (iterator.hasNext()){
            DnieCard card = iterator.next();
            DnieSession ses = currentCards.get(card);
            try {
                Enumeration<X509Certificate> certs = driver.getCerts(ses);
                if (certs != null){
                    while (certs.hasMoreElements()){
                        X509Certificate cert = certs.nextElement();
                        list.add(cert.getSubjectDN().toString());
                    }
                }
                Enumeration<Key> keys = driver.getKeys(ses);
                if (keys != null){
                    while (keys.hasMoreElements()){
                        Key key = keys.nextElement();
                        list.add("KEY-"+((DniePrivateKey)key).getCertificate().getSubjectDN().toString());
                    }
                }
            } catch (DnieDriverException ex){
                
            } catch (DnieDriverPinException ex){
                
            } catch (InvalidCardException ex){
                
            }
            
        }
        return Collections.enumeration(list);
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        updateCards();
        String subject = alias;
        if (subject.startsWith(KEY_ALIAS_PREFIX)){
           subject = subject.substring(KEY_ALIAS_PREFIX.length());
        }
        DnieSession session = getDnieSession4SubjectDN(subject);
        if (session != null){
            return true;
        }
        return false;
    }

    @Override
    public int engineSize() {
        updateCards();
        return (currentCards.size() * 2);
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        if (engineContainsAlias(alias)){
            return alias.startsWith(KEY_ALIAS_PREFIX);
        }
        return false;
        
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        if (engineContainsAlias(alias)){
            return (!alias.startsWith(KEY_ALIAS_PREFIX));
        }
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        if (cert instanceof X509Certificate){
            String alias = ((X509Certificate)cert).getSubjectDN().toString();
            DnieSession session = getDnieSession4SubjectDN(alias);
            if (session != null){
               return alias; 
            }
        }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {

    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private DnieSession getDnieSession4SubjectDN(String subject){
        Iterator<DnieCard> iterator = currentCards.keySet().iterator();
        while (iterator.hasNext()){
            DnieCard card = iterator.next();
            try {
                if (card.hasSubject(subject)){
                    return currentCards.get(card);                        
                }
            } catch (InvalidCardException ex){
                // try next card
            }
        }
        
        return null;
    }
    
    private void updateCards(){
        Enumeration <DnieCard> cards = driver.getCards();
        while (cards.hasMoreElements()){
            DnieCard card = cards.nextElement();
            DnieSession session;
            if (currentCards.containsKey(card)){
                // use current session
                session = currentCards.get(card);
            } else {
                session = driver.createSession(card);
                currentCards.put(card,session);
            }
        }
        Iterator<DnieCard> iterator = currentCards.keySet().iterator();
        while (iterator.hasNext()){
            DnieCard card = iterator.next();
            if (!card.isValid()){
                currentCards.remove(card);                        
            }
        }
    }
    
}
