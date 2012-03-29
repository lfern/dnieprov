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

import org.dnieprov.driver.utils.ByteArrayUtils;
import org.dnieprov.driver.utils.bertlv.BerTlv;
import org.dnieprov.driver.utils.bertlv.BerTlvIdentifier;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Implements the secure channel established with DNIe
 * @author luis
 */
final class DnieSecureChannel extends CardChannel{

    private byte kenc[];
    private byte kmac[];
    private byte scc[];
    private CardChannel channel;
    
    private static final BerTlvIdentifier TLV_DATA_TAG = new BerTlvIdentifier(0x87);
    private static final BerTlvIdentifier TLV_LE_TAG = new BerTlvIdentifier(0x97);
    private static final BerTlvIdentifier TLV_MAC_TAG = new BerTlvIdentifier(0x8e);
    private static final BerTlvIdentifier TLV_SW_TAG = new BerTlvIdentifier(0x99);
    public DnieSecureChannel(CardChannel channel,byte kenc[],byte kmac[],byte scc[]) {
        this.kenc = kenc;
        this.kmac = kmac;
        this.scc = scc;
        this.channel = channel;
        
    }

    @Override
    public void close() throws CardException {
        Arrays.fill(kenc,(byte)0x0);
        Arrays.fill(kmac,(byte)0x0);
        Arrays.fill(scc,(byte)0x0);
        channel = null;
    }

    @Override
    public Card getCard() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getChannelNumber() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU capdu) throws CardException {
        byte cla      = (byte)(capdu.getCLA() | 0x0c);
        byte ins      = (byte)capdu.getINS();
        byte p1       = (byte)capdu.getP1();
        byte p2       = (byte)capdu.getP2();
        int dataBytes = capdu.getNc();
        byte data[]   = capdu.getData();
        int le        = capdu.getNe();
        try {
            // CLA + INS + P1 + P2 + [ Padding(TLV_DATOS) ] + TLV_LC 
            
            byte tlvDataIn[];
            byte tlvLeIn[];
            byte macBuf[];
            
            BerTlv tmpTlv = new BerTlv();
            
            if (data.length != 0){
                tmpTlv.setTag(TLV_DATA_TAG);
                tmpTlv.setValue(ByteArrayUtils.prepend((byte)0x01,cipher(ByteArrayUtils.padding7816(data,dataBytes),true)));
                tlvDataIn = tmpTlv.getBytes();
            } else {
                tlvDataIn = new byte[0];
            }
            
            if (le != 0){
                tmpTlv.setTag(TLV_LE_TAG);
                tmpTlv.setValue(new byte[]{(byte)le});
                tlvLeIn = tmpTlv.getBytes();
            } else {
                tlvLeIn = new byte[0];
            }
            
            byte tlv[] = ByteArrayUtils.concat(tlvDataIn,tlvLeIn);
            
            macBuf = ByteArrayUtils.padding7816(
                        ByteArrayUtils.concat(
                            ByteArrayUtils.padding7816(cla, ins, p1, p2),
                            tlv));
            tmpTlv.setTag(TLV_MAC_TAG);
            tmpTlv.setValue(genmac(macBuf,nextScc()));
            byte tlvmac[] = tmpTlv.getBytes();
            ApduCommand ciphCommand = new ApduCommand("CIFRADO",cla,ins,p1,p2);
            ciphCommand.setData(ByteArrayUtils.concat(tlv,tlvmac));
            
            
            byte result[] = ciphCommand.exec(channel);
            
            if (ciphCommand.getLastSw() != ApduCommand.SW_OK){
                return new ResponseAPDU(ByteArrayUtils.concat(ApduCommand.EMPTY,ciphCommand.getLastSw1(),ciphCommand.getLastSw2()));
            }
            // coger los tres TLVs
            // 0x87 datos, 0x99 estado, 0x8e mac
            
            BerTlv berTlv = new BerTlv();
            ByteArrayInputStream bais = new ByteArrayInputStream(result);
            berTlv.decode(bais);
            
            BerTlv tlvDatos = null;
            if (berTlv.getTag().equals(TLV_DATA_TAG)){
                tlvDatos = berTlv;
                berTlv = new BerTlv();
                berTlv.decode(bais);
            }
            BerTlv tlvEstado = null;
            if (berTlv.getTag().equals(TLV_SW_TAG)){
                tlvEstado = berTlv;
                berTlv = new BerTlv();
                berTlv.decode(bais);
            }
                   
            BerTlv tlvMac = null;
            if (berTlv.getTag().equals(TLV_MAC_TAG)){
                tlvMac = berTlv;
            }
            
            byte respMac[];
            if (tlvDatos != null){
                respMac = genmac(ByteArrayUtils.padding7816(ByteArrayUtils.concat(tlvDatos.getBytes(),tlvEstado.getBytes())),nextScc());
            } else {
                respMac = genmac(ByteArrayUtils.padding7816(tlvEstado.getBytes()),nextScc());
            }
            
            if (!Arrays.equals(respMac, ByteArrayUtils.subArray(tlvMac.getBytes(),2,4))){
                throw new CardException("Error comprobando los MACs");
            }
            byte e[] = tlvEstado.getBytes();
            
            if (tlvDatos != null){
                byte datos[] = tlvDatos.getValue();
                byte dec[] = cipher(ByteArrayUtils.subArray(datos,1,datos.length-1),false);
                //System.out.println(">>"+ApduCommand.toString(dec));
                dec = ByteArrayUtils.removePadding7816(dec);
                //System.out.println(">>"+ApduCommand.toString(dec));
                return new ResponseAPDU(ByteArrayUtils.concat(dec,e[2],e[3]));
            } else {
                return new ResponseAPDU(ByteArrayUtils.concat(new byte[0],e[2],e[3]));
            }
                
        } catch (NoSuchAlgorithmException ex){
            throw new CardException(ex);
        } catch (NoSuchPaddingException ex){
            throw new CardException(ex);
        } catch (InvalidKeyException ex){
            throw new CardException(ex);
        } catch (InvalidAlgorithmParameterException ex){
            throw new CardException(ex);
        } catch (IllegalBlockSizeException ex){
            throw new CardException(ex);
        } catch (BadPaddingException ex){
            throw new CardException(ex);
        }
        
    }

    @Override
    public int transmit(ByteBuffer bb, ByteBuffer bb1) throws CardException {
        throw new UnsupportedOperationException("Not supported yet.");
    }    
    
    private byte[] cipher(byte data[],boolean encrypt) throws NoSuchAlgorithmException,BadPaddingException,IllegalBlockSizeException,
            InvalidAlgorithmParameterException,InvalidKeyException,NoSuchPaddingException{

        int dir = encrypt ? Cipher.ENCRYPT_MODE: Cipher.DECRYPT_MODE;
        byte[] keyTdesBytes = new byte[24];
        System.arraycopy(kenc, 0, keyTdesBytes, 0, 16);
        System.arraycopy(kenc, 0, keyTdesBytes, 16, 8);
        byte[] ivBytes = new byte[8];
        for (int i=0;i<8;i++){
            ivBytes[i] = 0x00;
        }
        SecretKey keyTdes = new SecretKeySpec(keyTdesBytes, "DESede");
        Cipher des = Cipher.getInstance("DESede/CBC/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        des.init(dir, keyTdes, iv);
        return des.doFinal(data);
        
    } 
    private byte[] genmac(byte data[],byte localScc[])throws BadPaddingException,IllegalBlockSizeException,InvalidAlgorithmParameterException,
            InvalidKeyException,NoSuchAlgorithmException,NoSuchPaddingException{
        byte keyDesBytes[] = new byte[8];
        System.arraycopy(kmac, 0, keyDesBytes, 0, 8);
        SecretKey keydes = new SecretKeySpec(keyDesBytes, "DES");
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        
        
        IvParameterSpec iv = new IvParameterSpec(localScc);
        des.init(Cipher.ENCRYPT_MODE, keydes);
        byte tmp[] = des.doFinal(localScc);
        int i = 0;
        for (;i<(data.length-8);i+=8){
            try {
                tmp = ByteArrayUtils.xor(tmp,ByteArrayUtils.subArray(data, i, 8));
            } catch(Exception ex){
                throw new NoSuchAlgorithmException(ex);
            }
            iv = new IvParameterSpec(localScc);
            des.init(Cipher.ENCRYPT_MODE, keydes);
            tmp = des.doFinal(tmp);
        }
        tmp = ByteArrayUtils.xor(tmp,ByteArrayUtils.subArray(data, i, 8));
        byte[] keyTdesBytes = new byte[24];
        System.arraycopy(kmac, 0, keyTdesBytes, 0, 16);
        System.arraycopy(kmac, 0, keyTdesBytes, 16, 8);
        SecretKey keyTdes = new SecretKeySpec(keyTdesBytes, "DESede");
        des = Cipher.getInstance("DESede/ECB/NoPadding");
        iv = new IvParameterSpec(localScc);
        des.init(Cipher.ENCRYPT_MODE, keyTdes);
        tmp = des.doFinal(tmp);
        return ByteArrayUtils.subArray(tmp,0,4);
        
    }
    private byte[] nextScc(){
        byte tmp[] = ByteArrayUtils.increment(scc);
        System.arraycopy(tmp, tmp.length-8, scc, 0, 8);
        return scc;
    }
    
}
