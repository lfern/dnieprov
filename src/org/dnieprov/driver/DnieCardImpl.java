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
package org.dnieprov.driver;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

/**
 * Contents info for a DNIe card.
 * @author luis
 */
/**  TODO: improve session handling */

final class DnieCardImpl {
    private final byte[] cardId;
    private final CardTerminal cardTerminal;
    private final CardChannel cardChannel;
    private DnieSecureChannel secureChannel = null;
    private Hashtable<DnieSession,Boolean> sessions = null;
    private boolean valid = true;
    private Hashtable <String,DnieP15Record> p15List = new Hashtable();
    private Hashtable<X509Certificate,String> certList = new Hashtable();
    private ArrayList<String> subjects = new ArrayList();
    
    
    public DnieCardImpl(byte[] cardId,CardTerminal cardTerminal,CardChannel cardChannel){
        if (cardId != null)
            this.cardId = Arrays.copyOf(cardId,cardId.length);
        else 
            this.cardId = null;
        this.cardTerminal = cardTerminal;
        this.cardChannel = cardChannel;
        sessions = new Hashtable();
    }

    public byte[] getCardId(){
        return Arrays.copyOf(cardId, cardId.length);
    }

    public CardTerminal getCardTerminal(){
        return cardTerminal;
    }
    
    public CardChannel getCardChannel(){
        return cardChannel;    
    }

    public void setSecureChannel(DnieSecureChannel secureChannel){
        this.secureChannel = secureChannel;
        Iterator<DnieSession> iterator = sessions.keySet().iterator();
        while (iterator.hasNext()){
            sessions.put(iterator.next(),Boolean.FALSE);
        }
    }

    public DnieSession createSession(){
        DnieSession sess = new DnieSession(new DnieCard(this));
        sessions.put(sess, Boolean.FALSE);
        return sess;
    }
    public void destroySession(DnieSession session){
        sessions.remove(session);
    }
    
    public void setVerifySession(DnieSession ses, boolean val){
        if (sessions.containsKey(ses)){
            sessions.put(ses, Boolean.valueOf(val));
        }
    }
    public boolean isVerified(DnieSession ses){
        return sessions.get(ses).booleanValue();
    }
    public DnieSecureChannel getSecureChannel(){
        return secureChannel;
    }
    
    public void invalidate(){
        valid = false;
        p15List.clear();
        certList.clear();
        subjects.clear();
        if (cardId != null)
            Arrays.fill(cardId,(byte) 0x00);
        try{
            if (secureChannel != null)
                secureChannel.close();
        } catch (CardException ex){
            
        }
    }
         
    public boolean isValid(){
        return valid;
    }
    
    public void addP15(DnieP15Record record){
        p15List.put(record.getCkaId(),record);
    }
    
    public Iterator<DnieP15Record> getInfo(){
        return p15List.values().iterator();
    }
    
    public void addCertificate(String id,X509Certificate cert){
        certList.put(cert,id);
        subjects.add(cert.getSubjectDN().toString());
    }
    
    public void removeCerts(){
        certList.clear();
    }
    public boolean hasCerts(){
        return (certList.size() > 0);
    }
    public DnieP15Record getInfo4Cert(X509Certificate cert){
        String id = certList.get(cert);
        if (id != null){
            return p15List.get(id);
        }
        return null;
    }
    public Enumeration<X509Certificate> getCerts(DnieSession session){
        if (sessions.containsKey(session)){
            if (sessions.get(session)){
                return Collections.enumeration(certList.keySet());
            }
        }
        return Collections.enumeration(Arrays.asList(new X509Certificate[0]));
    }
    public boolean sessionIsVerified(DnieSession session){
        if (sessions.containsKey(session)){
            return sessions.get(session);
        }
        return false;
    }
    public boolean hasSubject(String subject){
        return subjects.contains(subject);
    }
}
