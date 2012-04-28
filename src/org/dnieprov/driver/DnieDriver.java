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

import java.awt.GraphicsEnvironment;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CardTerminals.State;
import javax.smartcardio.TerminalFactory;
import org.dnieprov.driver.exceptions.DnieDriverException;
import org.dnieprov.driver.exceptions.DnieDriverPinException;
import org.dnieprov.driver.exceptions.ApduErrorException;
import org.dnieprov.driver.exceptions.DnieUnexpectedException;
import org.dnieprov.driver.exceptions.InvalidCardException;
import org.dnieprov.driver.exceptions.NoReadersFoundException;
import org.dnieprov.driver.exceptions.SecureChannelException;
import org.dnieprov.driver.utils.DigestInfo;

/**
 * Driver 
 * @author luis
 */

/** TODO: exception handling and card insertion/removal thread*/

public final class DnieDriver {
    
    private final DnieCardList cardList;
    private final boolean need2Verify4Certs;
    private static final String title = "DNIe Java Driver 1.2";
    private final static TerminalFactory factory = TerminalFactory.getDefault();
    private volatile EventWaitThread thread = null;
    
    public DnieDriver(){
        /** required for correct auto GET RESPONSE handling */
        System.setProperty("sun.security.smartcardio.t0GetResponse","false");
        /** TODO: CERT reconstrution */
        need2Verify4Certs = Boolean.parseBoolean(System.getProperty("org.dnieprov.need2Verify4Certs","true"));
        cardList = new DnieCardList();
    }
    private void startThread(){
        synchronized(this){
            if (thread == null){
                thread = new EventWaitThread();
                thread.start();
                Runtime.getRuntime().addShutdownHook(new Thread() {
                    @Override
                    public void run() {
                        stopThread();
                    }
                });            
            }
        }
        
    }
    private void stopThread(){
        synchronized(this){
            if (thread != null){
                thread.requestStop();
                thread = null;
            }
        }
    }
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        stopThread();
    }     
    public void init() throws DnieDriverException{
        
        try {
            initCards();
        } catch (CardException ex){
            throw new DnieDriverException(ex);
        } catch (NoReadersFoundException ex){
            throw new DnieDriverException(ex);
        } catch (ApduErrorException ex){
            throw new DnieDriverException(ex);
        }
        startThread();
        
    }
    
    public Enumeration<DnieCard> getCards(){
        return Collections.enumeration(cardList.arrayListCopy());
    }
    public Enumeration<X509Certificate> getCerts(DnieSession session) throws DnieDriverException,DnieDriverPinException,InvalidCardException{
        try {
            if (session.getCard().getCardImpl().isValid()){
                if (session.getCard().getCardImpl().getSecureChannel() == null){
                    setSecureChannel(session.getCard().getCardImpl());
                }
            }
            if (need2Verify4Certs){
                // verify
                DnieInterface inter = new DnieInterface(session.getCard().getCardImpl());
                if ((!session.getCard().getCardImpl().sessionIsVerified(session))){
                    // verify for this session
                    if (verify(inter)){
                        session.getCard().getCardImpl().setVerifySession(session, true);
                    }
                }
                if (!session.getCard().getCardImpl().hasCerts()){
                    setCerts(inter,session.getCard().getCardImpl());
                }
            } else {
                // CERT reconstruction
                throw new UnsupportedOperationException("Not supported yet.");
            }
            
            return session.getCard().getCardImpl().getCerts(session);
        } catch (SecureChannelException ex){
            throw new DnieDriverException(ex);
        } catch (CardException ex){
            throw new DnieDriverException(ex);
        } catch (ApduErrorException ex){
            throw new DnieDriverException(ex);
        }
    }
    
    public DnieSession createSession(DnieCard card){
        return card.getCardImpl().createSession();
    }
    public void destroySession(DnieSession session){
        session.getCard().getCardImpl().destroySession(session);
    }
    
    public Enumeration<Key> getKeys(DnieSession session) throws DnieDriverException,DnieDriverPinException,InvalidCardException{
        ArrayList<Key> list = new ArrayList();
        Enumeration<X509Certificate> certs = getCerts(session);
        while(certs.hasMoreElements()){
            list.add(new DniePrivateKey(session, certs.nextElement()));
        }
        return Collections.enumeration(list);
    }
    private boolean verify(DnieInterface inter) throws DnieUnexpectedException,DnieDriverPinException, CardException, ApduErrorException,InvalidCardException {
        char [] password = null;
        PasswordCallback passCall = null;
        String msg = null;
        String msgError = null;
        String triesMsg = "";
        if (GraphicsEnvironment.isHeadless()){
            passCall = new PasswordConsoleCallback();
            msg = "Escriba el PIN de la tarjeta:";
            msgError= "AVISO: Le quedan % intentos antes de bloquear la tarjeta\n";
        } else {
            passCall = new PasswordGuiCallback();
            msg = "%<font color='black'>Escriba el PIN del DNIe</font>";
            msgError = "<font color='red'>AVISO: Le quedan % intentos antes de bloquear la tarjeta</font><br><br>";
        }
        while(true){
            
            password = passCall.getPassword(title,msg.replaceAll("%", triesMsg));
            if (password == null) {
                return false;
            }

            int ret = inter.authenticate(password);
            if (ret == ApduCommand.SW_OK){
                return true;
            }
            if ((ret >> 8) != 0x00){
                throw new ApduErrorException(ret);
            }
            triesMsg = msgError.replaceAll("%", String.valueOf(ret));
            passCall.showMessage(title,triesMsg);

        }                
    }
    public byte[] sign(DnieSession session,String algorithm,
            byte[] digest,X509Certificate cert)throws DnieDriverException,
            DnieDriverPinException, NoSuchAlgorithmException, InvalidCardException{
        try {
            if (session.getCard().getCardImpl().isValid()){
                if (session.getCard().getCardImpl().getSecureChannel() == null){
                    setSecureChannel(session.getCard().getCardImpl());
                }
            }
            DnieP15Record rec = session.getCard().getCardImpl().getInfo4Cert(cert);
            if (rec == null){
                throw new DnieDriverException("this session is invalid");
            }
            DnieInterface inter = new DnieInterface(session.getCard().getCardImpl());
            if ((!session.getCard().getCardImpl().sessionIsVerified(session))){
                if (verify(inter)){
                    session.getCard().getCardImpl().setVerifySession(session, true);
                }
            }
            ParamReference param = new ParamReference();
            int ret = inter.sign(rec.getCkaId(),DigestInfo.encode(algorithm, digest), digest, param);
            if (ret != ApduCommand.SW_OK){
                throw new ApduErrorException(ret);
            }
            return (byte[]) param.getValue();
            
        } catch (SecureChannelException ex){
            throw new DnieDriverException(ex);
        } catch (CardException ex){
            throw new DnieDriverException(ex);
        } catch (ApduErrorException ex){
            throw new DnieDriverException(ex);
        } catch (IOException ex){
            throw new DnieUnexpectedException("Error getting algorithm id for digest info",ex);
        }
    }
    
    
    private void initCards() throws CardException,NoReadersFoundException,DnieDriverException,ApduErrorException{
        cardList.clear();
        //TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals;
        try {
            terminals = factory.terminals().list(State.CARD_PRESENT);
        } catch (CardException ex){
            return;
        }

        Iterator it = terminals.iterator();
        while (it.hasNext()){
            CardTerminal terminal = (CardTerminal)(it.next());
            if (!terminal.isCardPresent())
                continue;

            // establish a connection with the card
            // "T=0", "T=1", "T=CL" or "*"
            Card card = terminal.connect("T=0");
            //card.beginExclusive();

            ATR atr = card.getATR();
            if (DnieInterface.isDNI(atr.getBytes())){
                addCard(terminal,card);
            }

        }
        
    }
    private void setSecureChannel(DnieCardImpl cardImpl) throws SecureChannelException{
        int ret;
        try {
            DnieInterface inter = new DnieInterface(cardImpl);
            ret = inter.secureChannel();
            if (ret != ApduCommand.SW_OK){
                throw new ApduErrorException(ret);
            }
        } catch (Exception ex){
            throw new SecureChannelException(ex);
        }
    }    
    private byte[] deflate(byte [] zlib) throws DnieUnexpectedException{
        byte [] buf = null;
        SecureByteBuffer buffer = new SecureByteBuffer();
        try {
            Inflater decompressor = new Inflater();
            decompressor.setInput(zlib,8,zlib.length-8);

            // Decompress the data
            buf = new byte[1024];
            while (!decompressor.finished()) {
                int count = decompressor.inflate(buf);
                if (count == 0){
                    throw new DataFormatException();
                }
                buffer.write(buf, 0, count);
            }

            // Get the decompressed data
            return buffer.getByteArray();
        } catch (DataFormatException ex){
            throw new DnieUnexpectedException("Error cert compression");
        } finally {
            if (buf != null) Arrays.fill(buf,DnieInterface.NULL_BYTE);
            buffer.clearAll();
        }
        
    }
    private void setInfo(DnieInterface inter,DnieCardImpl card) throws DnieDriverException,InvalidCardException{
        try {
            ParamReference param = new ParamReference();
            
            int apduError = inter.getPkcs15CertificateInfo(param);            
            if (apduError != ApduCommand.SW_OK){
                throw new ApduErrorException(apduError);
            }
            DnieP15Decoder dec = (DnieP15Decoder) param.getValue();

            DnieP15Record authRec =  dec.get("CertAutenticacion");
            DnieP15Record signRec =  dec.get("CertFirmaDigital");

            card.addP15(signRec);
            card.addP15(authRec);
        } catch (CardException ex){
            throw new DnieDriverException(ex);
        } catch (ApduErrorException ex){
            throw new DnieDriverException(ex);
        }finally{
            
        }
        
    }
    private void setCerts(DnieInterface inter,DnieCardImpl card) throws DnieDriverException,InvalidCardException{
        byte [] zlibCert = null;
        byte [] unzCert = null;
        try {
            Iterator<DnieP15Record> iterator = card.getInfo();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            while (iterator.hasNext()){
                DnieP15Record rec = iterator.next();
                ParamReference param = new ParamReference();
                int apduError = inter.getCertificate(rec.getPath(), param);
                if (apduError != ApduCommand.SW_OK){
                    throw new ApduErrorException(apduError);
                }
                zlibCert = (byte []) param.getValue();
                unzCert = deflate(zlibCert);
                card.addCertificate(rec.getCkaId(),(X509Certificate)cf.generateCertificate(new ByteArrayInputStream(unzCert)));    
                Arrays.fill(zlibCert,DnieInterface.NULL_BYTE);
                Arrays.fill(unzCert,DnieInterface.NULL_BYTE);
                zlibCert = null;
                unzCert = null;
            }
        } catch (CertificateException ex){
            card.removeCerts();
            throw new DnieUnexpectedException("Error decoding compressed certificate",ex);
        } catch (CardException ex){
            card.removeCerts();
            throw new DnieDriverException(ex);
        } catch (ApduErrorException ex){
            card.removeCerts();
            throw new DnieDriverException(ex);
        }finally{
            if (zlibCert != null) Arrays.fill(zlibCert,DnieInterface.NULL_BYTE);
            if (unzCert != null) Arrays.fill(unzCert,DnieInterface.NULL_BYTE);
            
        }
        
    }
    private void addCard(CardTerminal terminal,Card card) throws CardException,ApduErrorException,DnieDriverException{
        ParamReference param = new ParamReference();
        CardChannel channel = card.getBasicChannel();
        int apduError = DnieInterface.getChipInfo(channel,param);
        if (apduError != ApduCommand.SW_OK){
            throw new ApduErrorException(apduError);
        }
        byte [] serialNumber = (byte []) param.getValue();
        DnieCardImpl cardImpl = new DnieCardImpl(serialNumber,terminal,channel);
        DnieInterface inter = new DnieInterface(cardImpl);
        try {
            setInfo(inter, cardImpl);
            cardList.add(new DnieCard(cardImpl));
        } catch (InvalidCardException ex){
            // card not valid
        }
        
    }
    
    
    private class EventWaitThread extends Thread {
        private volatile boolean stop = false;
        private List<CardTerminal> list(CardTerminals.State state){
            List<CardTerminal> terminals;
            try {
                terminals = factory.terminals().list(state);
            } catch (CardException ex){
                return null;
            }

            return terminals;
        }
        public void requestStop() {
            stop = true;
        }        

        @Override
        public void run() {
            while (!stop) {
                try{
                    List<CardTerminal> terminalList = list(CardTerminals.State.CARD_REMOVAL);
                    if (terminalList != null){
                        for (CardTerminal terminal : terminalList) {
                            Iterator<DnieCard> list = cardList.iterator();
                            while (list.hasNext()){
                                DnieCard c = list.next();
                                if (c.getCardImpl().getCardTerminal().equals(terminal)){
                                    cardList.remove(c);
                                    c.getCardImpl().invalidate();
                                    break;
                                }
                            }
                        }
                    }
                    terminalList = list(CardTerminals.State.CARD_INSERTION);
                    if (terminalList != null){
                        for (CardTerminal terminal : terminalList) {
                            try {
                                Card card = terminal.connect("T=0");
                                ATR atr = card.getATR();
                                if (DnieInterface.isDNI(atr.getBytes())){
                                    Iterator<DnieCard> list = cardList.iterator();
                                    while (list.hasNext()){
                                        DnieCard c = list.next();
                                        if (c.getCardImpl().getCardTerminal().equals(terminal)){
                                            cardList.remove(c);
                                            c.getCardImpl().invalidate();
                                            break;
                                        }
                                    }
                                    try {
                                        addCard(terminal, card);
                                    } catch (Exception ex){
                                        // try again
                                        try {
                                            addCard(terminal, card);
                                        } catch (Exception ex2){
                                            ex2.printStackTrace();
                                        }
                                    }
                                }
                            } catch (CardException ex){
                                
                            }
                        }
                    }
                    boolean event = false;
                    while (!event){
                        try {
                            event = factory.terminals().waitForChange(5000);
                        } catch (CardException ex){
                            Thread.sleep(5000);
                        }
                    }
                } catch (InterruptedException e){
                    e.printStackTrace(); 
                }
            }
        }
    }    
}
