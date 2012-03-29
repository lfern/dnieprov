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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Iterator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import org.dnieprov.driver.exceptions.DnieKeyNotFoundException;
import org.dnieprov.driver.exceptions.DnieSecureChannelNotEstablished;
import org.dnieprov.driver.exceptions.DnieGettingCryptoProviderExcetion;
import org.dnieprov.driver.exceptions.DnieSettingSecureChannelException;
import org.dnieprov.driver.exceptions.DnieUnexpectedException;
import org.dnieprov.driver.exceptions.InvalidCardException;

/**
 * DNIe interface API
 * @author luis
 */

/** TODO: check if every buffer is cleared */
final class DnieInterface {

    private static final byte[] DNIe_ATR = {
        (byte)0x3B, (byte)0x7F, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x6A, (byte)0x44,
        (byte)0x4E, (byte)0x49, (byte)0x65, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x90, (byte)0x00
    };

    private static final byte[] DNIe_MASK = {
        (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF
    };
    
    private static final byte CHR_IFD[] = {
        (byte)0x20,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01
    };

    private static final byte masterFile[] = {
        0x4d,0x61,0x73,0x74,0x65,0x72,0x2e,0x46,0x69,0x6c,0x65
    };
    
    private static final byte CA_COMPONENT_MODULUS[] = {
        (byte)0xEA,(byte)0xDE,(byte)0xDA,(byte)0x45,(byte)0x53,(byte)0x32,(byte)0x94,(byte)0x50,
        (byte)0x39,(byte)0xDA,(byte)0xA4,(byte)0x04,(byte)0xC8,(byte)0xEB,(byte)0xC4,(byte)0xD3,
        (byte)0xB7,(byte)0xF5,(byte)0xDC,(byte)0x86,(byte)0x92,(byte)0x83,(byte)0xCD,(byte)0xEA,
        (byte)0x2F,(byte)0x10,(byte)0x1E,(byte)0x2A,(byte)0xB5,(byte)0x4F,(byte)0xB0,(byte)0xD0,
        (byte)0xB0,(byte)0x3D,(byte)0x8F,(byte)0x03,(byte)0x0D,(byte)0xAF,(byte)0x24,(byte)0x58,
        (byte)0x02,(byte)0x82,(byte)0x88,(byte)0xF5,(byte)0x4C,(byte)0xE5,(byte)0x52,(byte)0xF8,
        (byte)0xFA,(byte)0x57,(byte)0xAB,(byte)0x2F,(byte)0xB1,(byte)0x03,(byte)0xB1,(byte)0x12,
        (byte)0x42,(byte)0x7E,(byte)0x11,(byte)0x13,(byte)0x1D,(byte)0x1D,(byte)0x27,(byte)0xE1,
        (byte)0x0A,(byte)0x5B,(byte)0x50,(byte)0x0E,(byte)0xAA,(byte)0xE5,(byte)0xD9,(byte)0x40,
        (byte)0x30,(byte)0x1E,(byte)0x30,(byte)0xEB,(byte)0x26,(byte)0xC3,(byte)0xE9,(byte)0x06,
        (byte)0x6B,(byte)0x25,(byte)0x71,(byte)0x56,(byte)0xED,(byte)0x63,(byte)0x9D,(byte)0x70,
        (byte)0xCC,(byte)0xC0,(byte)0x90,(byte)0xB8,(byte)0x63,(byte)0xAF,(byte)0xBB,(byte)0x3B,
        (byte)0xFE,(byte)0xD8,(byte)0xC1,(byte)0x7B,(byte)0xE7,(byte)0x67,(byte)0x30,(byte)0x34,
        (byte)0xB9,(byte)0x82,(byte)0x3E,(byte)0x97,(byte)0x7E,(byte)0xD6,(byte)0x57,(byte)0x25,
        (byte)0x29,(byte)0x27,(byte)0xF9,(byte)0x57,(byte)0x5B,(byte)0x9F,(byte)0xFF,(byte)0x66,
        (byte)0x91,(byte)0xDB,(byte)0x64,(byte)0xF8,(byte)0x0B,(byte)0x5E,(byte)0x92,(byte)0xCD
    };
    
    private static final byte CA_COMPONENT_EXPONENT[] = {(byte)0x01,(byte)0x00,(byte)0x01};
    
    private static final byte C_CV_CA[] = {
        (byte)0x7F,(byte)0x21,(byte)0x81,(byte)0xCE,(byte)0x5F,(byte)0x37,(byte)0x81,(byte)0x80,
        (byte)0x3C,(byte)0xBA,(byte)0xDC,(byte)0x36,(byte)0x84,(byte)0xBE,(byte)0xF3,(byte)0x20,
        (byte)0x41,(byte)0xAD,(byte)0x15,(byte)0x50,(byte)0x89,(byte)0x25,(byte)0x8D,(byte)0xFD,
        (byte)0x20,(byte)0xC6,(byte)0x91,(byte)0x15,(byte)0xD7,(byte)0x2F,(byte)0x9C,(byte)0x38,
        (byte)0xAA,(byte)0x99,(byte)0xAD,(byte)0x6C,(byte)0x1A,(byte)0xED,(byte)0xFA,(byte)0xB2,
        (byte)0xBF,(byte)0xAC,(byte)0x90,(byte)0x92,(byte)0xFC,(byte)0x70,(byte)0xCC,(byte)0xC0,
        (byte)0x0C,(byte)0xAF,(byte)0x48,(byte)0x2A,(byte)0x4B,(byte)0xE3,(byte)0x1A,(byte)0xFD,
        (byte)0xBD,(byte)0x3C,(byte)0xBC,(byte)0x8C,(byte)0x83,(byte)0x82,(byte)0xCF,(byte)0x06,
        (byte)0xBC,(byte)0x07,(byte)0x19,(byte)0xBA,(byte)0xAB,(byte)0xB5,(byte)0x6B,(byte)0x6E,
        (byte)0xC8,(byte)0x07,(byte)0x60,(byte)0xA4,(byte)0xA9,(byte)0x3F,(byte)0xA2,(byte)0xD7,
        (byte)0xC3,(byte)0x47,(byte)0xF3,(byte)0x44,(byte)0x27,(byte)0xF9,(byte)0xFF,(byte)0x5C,
        (byte)0x8D,(byte)0xE6,(byte)0xD6,(byte)0x5D,(byte)0xAC,(byte)0x95,(byte)0xF2,(byte)0xF1,
        (byte)0x9D,(byte)0xAC,(byte)0x00,(byte)0x53,(byte)0xDF,(byte)0x11,(byte)0xA5,(byte)0x07,
        (byte)0xFB,(byte)0x62,(byte)0x5E,(byte)0xEB,(byte)0x8D,(byte)0xA4,(byte)0xC0,(byte)0x29,
        (byte)0x9E,(byte)0x4A,(byte)0x21,(byte)0x12,(byte)0xAB,(byte)0x70,(byte)0x47,(byte)0x58,
        (byte)0x8B,(byte)0x8D,(byte)0x6D,(byte)0xA7,(byte)0x59,(byte)0x22,(byte)0x14,(byte)0xF2,
        (byte)0xDB,(byte)0xA1,(byte)0x40,(byte)0xC7,(byte)0xD1,(byte)0x22,(byte)0x57,(byte)0x9B,
        (byte)0x5F,(byte)0x38,(byte)0x3D,(byte)0x22,(byte)0x53,(byte)0xC8,(byte)0xB9,(byte)0xCB,
        (byte)0x5B,(byte)0xC3,(byte)0x54,(byte)0x3A,(byte)0x55,(byte)0x66,(byte)0x0B,(byte)0xDA,
        (byte)0x80,(byte)0x94,(byte)0x6A,(byte)0xFB,(byte)0x05,(byte)0x25,(byte)0xE8,(byte)0xE5,
        (byte)0x58,(byte)0x6B,(byte)0x4E,(byte)0x63,(byte)0xE8,(byte)0x92,(byte)0x41,(byte)0x49,
        (byte)0x78,(byte)0x36,(byte)0xD8,(byte)0xD3,(byte)0xAB,(byte)0x08,(byte)0x8C,(byte)0xD4,
        (byte)0x4C,(byte)0x21,(byte)0x4D,(byte)0x6A,(byte)0xC8,(byte)0x56,(byte)0xE2,(byte)0xA0,
        (byte)0x07,(byte)0xF4,(byte)0x4F,(byte)0x83,(byte)0x74,(byte)0x33,(byte)0x37,(byte)0x37,
        (byte)0x1A,(byte)0xDD,(byte)0x8E,(byte)0x03,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x01,
        (byte)0x42,(byte)0x08,(byte)0x65,(byte)0x73,(byte)0x52,(byte)0x44,(byte)0x49,(byte)0x60,
        (byte)0x00,(byte)0x06
    };
    
    private static final byte C_CV_IFD[] = {
        (byte)0x7f,(byte)0x21,(byte)0x81,(byte)0xcd,(byte)0x5f,(byte)0x37,(byte)0x81,(byte)0x80,
        (byte)0x82,(byte)0x5b,(byte)0x69,(byte)0xc6,(byte)0x45,(byte)0x1e,(byte)0x5f,(byte)0x51,
        (byte)0x70,(byte)0x74,(byte)0x38,(byte)0x5f,(byte)0x2f,(byte)0x17,(byte)0xd6,(byte)0x4d,
        (byte)0xfe,(byte)0x2e,(byte)0x68,(byte)0x56,(byte)0x75,(byte)0x67,(byte)0x09,(byte)0x4b,
        (byte)0x57,(byte)0xf3,(byte)0xc5,(byte)0x78,(byte)0xe8,(byte)0x30,(byte)0xe4,(byte)0x25,
        (byte)0x57,(byte)0x2d,(byte)0xe8,(byte)0x28,(byte)0xfa,(byte)0xf4,(byte)0xde,(byte)0x1b,
        (byte)0x01,(byte)0xc3,(byte)0x94,(byte)0xe3,(byte)0x45,(byte)0xc2,(byte)0xfb,(byte)0x06,
        (byte)0x29,(byte)0xa3,(byte)0x93,(byte)0x49,(byte)0x2f,(byte)0x94,(byte)0xf5,(byte)0x70,
        (byte)0xb0,(byte)0x0b,(byte)0x1d,(byte)0x67,(byte)0x77,(byte)0x29,(byte)0xf7,(byte)0x55,
        (byte)0xd1,(byte)0x07,(byte)0x02,(byte)0x2b,(byte)0xb0,(byte)0xa1,(byte)0x16,(byte)0xe1,
        (byte)0xd7,(byte)0xd7,(byte)0x65,(byte)0x9d,(byte)0xb5,(byte)0xc4,(byte)0xac,(byte)0x0d,
        (byte)0xde,(byte)0xab,(byte)0x07,(byte)0xff,(byte)0x04,(byte)0x5f,(byte)0x37,(byte)0xb5,
        (byte)0xda,(byte)0xf1,(byte)0x73,(byte)0x2b,(byte)0x54,(byte)0xea,(byte)0xb2,(byte)0x38,
        (byte)0xa2,(byte)0xce,(byte)0x17,(byte)0xc9,(byte)0x79,(byte)0x41,(byte)0x87,(byte)0x75,
        (byte)0x9c,(byte)0xea,(byte)0x9f,(byte)0x92,(byte)0xa1,(byte)0x78,(byte)0x05,(byte)0xa2,
        (byte)0x7c,(byte)0x10,(byte)0x15,(byte)0xec,(byte)0x56,(byte)0xcc,(byte)0x7e,(byte)0x47,
        (byte)0x1a,(byte)0x48,(byte)0x8e,(byte)0x6f,(byte)0x1b,(byte)0x91,(byte)0xf7,(byte)0xaa,
        (byte)0x5f,(byte)0x38,(byte)0x3c,(byte)0xad,(byte)0xfc,(byte)0x12,(byte)0xe8,(byte)0x56,
        (byte)0xb2,(byte)0x02,(byte)0x34,(byte)0x6a,(byte)0xf8,(byte)0x22,(byte)0x6b,(byte)0x1a,
        (byte)0x88,(byte)0x21,(byte)0x37,(byte)0xdc,(byte)0x3c,(byte)0x5a,(byte)0x57,(byte)0xf0,
        (byte)0xd2,(byte)0x81,(byte)0x5c,(byte)0x1f,(byte)0xcd,(byte)0x4b,(byte)0xb4,(byte)0x6f,
        (byte)0xa9,(byte)0x15,(byte)0x7f,(byte)0xdf,(byte)0xfd,(byte)0x79,(byte)0xec,(byte)0x3a,
        (byte)0x10,(byte)0xa8,(byte)0x24,(byte)0xcc,(byte)0xc1,(byte)0xeb,(byte)0x3c,(byte)0xe0,
        (byte)0xb6,(byte)0xb4,(byte)0x39,(byte)0x6a,(byte)0xe2,(byte)0x36,(byte)0x59,(byte)0x00,
        (byte)0x16,(byte)0xba,(byte)0x69,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x01,(byte)0x42,
        (byte)0x08,(byte)0x65,(byte)0x73,(byte)0x53,(byte)0x44,(byte)0x49,(byte)0x60,(byte)0x00,
        (byte)0x06
    };
    
    
    private static final byte IFD_MODULUS[] = {
        (byte)0xDB,(byte)0x2C,(byte)0xB4,(byte)0x1E,(byte)0x11,(byte)0x2B,(byte)0xAC,(byte)0xFA,
        (byte)0x2B,(byte)0xD7,(byte)0xC3,(byte)0xD3,(byte)0xD7,(byte)0x96,(byte)0x7E,(byte)0x84,
        (byte)0xFB,(byte)0x94,(byte)0x34,(byte)0xFC,(byte)0x26,(byte)0x1F,(byte)0x9D,(byte)0x09,
        (byte)0x0A,(byte)0x89,(byte)0x83,(byte)0x94,(byte)0x7D,(byte)0xAF,(byte)0x84,(byte)0x88,
        (byte)0xD3,(byte)0xDF,(byte)0x8F,(byte)0xBD,(byte)0xCC,(byte)0x1F,(byte)0x92,(byte)0x49,
        (byte)0x35,(byte)0x85,(byte)0xE1,(byte)0x34,(byte)0xA1,(byte)0xB4,(byte)0x2D,(byte)0xE5,
        (byte)0x19,(byte)0xF4,(byte)0x63,(byte)0x24,(byte)0x4D,(byte)0x7E,(byte)0xD3,(byte)0x84,
        (byte)0xE2,(byte)0x6D,(byte)0x51,(byte)0x6C,(byte)0xC7,(byte)0xA4,(byte)0xFF,(byte)0x78,
        (byte)0x95,(byte)0xB1,(byte)0x99,(byte)0x21,(byte)0x40,(byte)0x04,(byte)0x3A,(byte)0xAC,
        (byte)0xAD,(byte)0xFC,(byte)0x12,(byte)0xE8,(byte)0x56,(byte)0xB2,(byte)0x02,(byte)0x34,
        (byte)0x6A,(byte)0xF8,(byte)0x22,(byte)0x6B,(byte)0x1A,(byte)0x88,(byte)0x21,(byte)0x37,
        (byte)0xDC,(byte)0x3C,(byte)0x5A,(byte)0x57,(byte)0xF0,(byte)0xD2,(byte)0x81,(byte)0x5C,
        (byte)0x1F,(byte)0xCD,(byte)0x4B,(byte)0xB4,(byte)0x6F,(byte)0xA9,(byte)0x15,(byte)0x7F,
        (byte)0xDF,(byte)0xFD,(byte)0x79,(byte)0xEC,(byte)0x3A,(byte)0x10,(byte)0xA8,(byte)0x24,
        (byte)0xCC,(byte)0xC1,(byte)0xEB,(byte)0x3C,(byte)0xE0,(byte)0xB6,(byte)0xB4,(byte)0x39,
        (byte)0x6A,(byte)0xE2,(byte)0x36,(byte)0x59,(byte)0x00,(byte)0x16,(byte)0xBA,(byte)0x69
    };
    private static final byte IFD_PRIV_EXPONENT[] ={
        (byte)0x18,(byte)0xB4,(byte)0x4A,(byte)0x3D,(byte)0x15,(byte)0x5C,(byte)0x61,(byte)0xEB,
        (byte)0xF4,(byte)0xE3,(byte)0x26,(byte)0x1C,(byte)0x8B,(byte)0xB1,(byte)0x57,(byte)0xE3,
        (byte)0x6F,(byte)0x63,(byte)0xFE,(byte)0x30,(byte)0xE9,(byte)0xAF,(byte)0x28,(byte)0x89,
        (byte)0x2B,(byte)0x59,(byte)0xE2,(byte)0xAD,(byte)0xEB,(byte)0x18,(byte)0xCC,(byte)0x8C,
        (byte)0x8B,(byte)0xAD,(byte)0x28,(byte)0x4B,(byte)0x91,(byte)0x65,(byte)0x81,(byte)0x9C,
        (byte)0xA4,(byte)0xDE,(byte)0xC9,(byte)0x4A,(byte)0xA0,(byte)0x6B,(byte)0x69,(byte)0xBC,
        (byte)0xE8,(byte)0x17,(byte)0x06,(byte)0xD1,(byte)0xC1,(byte)0xB6,(byte)0x68,(byte)0xEB,
        (byte)0x12,(byte)0x86,(byte)0x95,(byte)0xE5,(byte)0xF7,(byte)0xFE,(byte)0xDE,(byte)0x18,
        (byte)0xA9,(byte)0x08,(byte)0xA3,(byte)0x01,(byte)0x1A,(byte)0x64,(byte)0x6A,(byte)0x48,
        (byte)0x1D,(byte)0x3E,(byte)0xA7,(byte)0x1D,(byte)0x8A,(byte)0x38,(byte)0x7D,(byte)0x47,
        (byte)0x46,(byte)0x09,(byte)0xBD,(byte)0x57,(byte)0xA8,(byte)0x82,(byte)0xB1,(byte)0x82,
        (byte)0xE0,(byte)0x47,(byte)0xDE,(byte)0x80,(byte)0xE0,(byte)0x4B,(byte)0x42,(byte)0x21,
        (byte)0x41,(byte)0x6B,(byte)0xD3,(byte)0x9D,(byte)0xFA,(byte)0x1F,(byte)0xAC,(byte)0x03,
        (byte)0x00,(byte)0x64,(byte)0x19,(byte)0x62,(byte)0xAD,(byte)0xB1,(byte)0x09,(byte)0xE2,
        (byte)0x8C,(byte)0xAF,(byte)0x50,(byte)0x06,(byte)0x1B,(byte)0x68,(byte)0xC9,(byte)0xCA,
        (byte)0xBD,(byte)0x9B,(byte)0x00,(byte)0x31,(byte)0x3C,(byte)0x0F,(byte)0x46,(byte)0xED
    };
    
    public static final byte NULL_BYTE = (byte) 0x00;
    private DnieCardImpl card;
    
    public DnieInterface(DnieCardImpl card){
        this.card = card;
    }

    public static boolean isDNI(byte [] atrCard){
        
        if(atrCard.length == DNIe_ATR.length) {
            for (int i=0;i<atrCard.length;i++){
                if((atrCard[i] & DNIe_MASK[i]) != (DNIe_ATR[i] & DNIe_MASK[i]))
                    return false;
            }
        }else{/*No es una tarjeta DNIe*/
                return false;
        }
        return true;
    }
    
    public int authenticate(char[] password) throws CardException,InvalidCardException{
        byte[] pass = new byte[password.length];
        for (int i = 0; i < password.length; i++) {
            pass[i] = (byte) password[i];
        }
        try {
            ApduCommand acVerify = acVerifyInstance();
            
            acVerify.setData(pass);

            acVerify.exec(card.getSecureChannel());

            if (acVerify.getLastSw1() == (byte)0x63){
                return acVerify.getLastSw2() & 0x03;
            }
            return acVerify.getLastSw();
        } finally {
            Arrays.fill(pass, NULL_BYTE);
        }
    }
    public static int getChipInfo(CardChannel channel,ParamReference param) throws CardException{
        ApduCommand acChipInfo = acChipInfoInstance();
        byte[] serialNumber = acChipInfo.exec(channel);
        int lastSW =  acChipInfo.getLastSw();
        if (lastSW != ApduCommand.SW_OK) return lastSW;
        param.setValue(serialNumber);
        return lastSW;
    }
    public int secureChannel() throws CardException,
            DnieGettingCryptoProviderExcetion,DnieSettingSecureChannelException,
            DnieUnexpectedException{
        byte[] randomBytes = null;
        byte[] challenge = null;
        byte[] kicc = null;
        byte[] kifd = null;
        byte [] serialNumber = null;
        ParamReference param = new ParamReference();


        RSAPublicKey iccPubkey = null;
        
        ApduCommand acChipInfo = acChipInfoInstance();
        ApduCommand acDniLoadCerts = acDniLoadCerts();
        ApduCommand acGetChallenge = acGetChallengeInstance();

        try {
            CardChannel channel = card.getCardChannel();
            int lastSW;

            serialNumber = acChipInfo.exec(channel);
            lastSW =  acChipInfo.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            // Verify certs
            lastSW = doCheckCertificate(channel, param); 
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            iccPubkey = (RSAPublicKey)param.getValue();
            // Load certs in card
            acDniLoadCerts.exec(channel);
            lastSW = acDniLoadCerts.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            // internal authentication

            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            randomBytes = new byte[8];
            sr.nextBytes(randomBytes);

            RSAPrivateKey ifdKey = getIfdRSAPrivateKey();

            lastSW = doInternalAuthentication(channel, randomBytes,ifdKey,iccPubkey,param);
            kicc = (byte[])param.getValue();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            // get challenge
            challenge = acGetChallenge.exec(channel);
            lastSW = acGetChallenge.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            lastSW = doExternalAuthentication(channel,serialNumber, challenge, ifdKey, iccPubkey, param);
            kifd = (byte[])param.getValue();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            card.setSecureChannel(doSecureChannelInstance(channel, randomBytes, challenge, kicc, kifd));

            return lastSW;
        } catch (NoSuchAlgorithmException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error setting secure channel",ex);
        } finally {
        if (randomBytes != null) Arrays.fill(randomBytes, NULL_BYTE);
        if (challenge != null) Arrays.fill(challenge, NULL_BYTE);
        if (kicc != null) Arrays.fill(kicc, NULL_BYTE);
        if (kifd != null) Arrays.fill(kifd, NULL_BYTE);
        if (serialNumber != null) Arrays.fill(serialNumber, NULL_BYTE);
            
        }
    }
    public int  getCertificates(ParamReference signCert,ParamReference authCert) throws CardException,
            DnieSecureChannelNotEstablished, DnieUnexpectedException,InvalidCardException{
        CardChannel secureChannel = card.getSecureChannel();
        DnieP15Decoder dec = null;
        byte[] result = null;
        SecureByteBuffer buffer = new SecureByteBuffer();
        
        int lastSW;
        if (secureChannel == null){
            throw new DnieSecureChannelNotEstablished("Error getting certificates from card");
        }
        
        ParamReference param = new ParamReference();
        try {
            lastSW = getPkcs15CertificateInfo(param);
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            dec = (DnieP15Decoder)param.getValue();
            
            DnieP15Record rec = dec.get("CertAutenticacion");
            if (rec == null) throw new DnieUnexpectedException("CertAutenticacion not found in pkcs15");
            
            byte path[] = rec.getPath();
            lastSW = getCertificate(path,param);
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            authCert.setValue(param.getValue());

            rec = dec.get("CertFirmaDigital");
            if (rec == null) throw new DnieUnexpectedException("CertFirmaDigital not found in pkcs15");
            
            path = rec.getPath();
            lastSW = getCertificate(path,param);
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            signCert.setValue(param.getValue());
            
            return lastSW;
        } finally{
            Arrays.asList(result,NULL_BYTE);
            buffer.clear();
        }
                   
    }        

    public int sign(String keyId,byte[] asn1DigestInfo,byte digest[],ParamReference outSignature) throws CardException,
            DnieSecureChannelNotEstablished,DnieKeyNotFoundException,InvalidCardException{
        CardChannel secureChannel = card.getSecureChannel();
        byte [] path = null;
        byte [] secData = {(byte)0x84,(byte)0x02,(byte)0x01,(byte)0x00};
        int lastSW;
        if (secureChannel == null){
            throw new DnieSecureChannelNotEstablished("Error getting certificates from card");
        }
        ApduCommand acManageSecurityEnvironment = acManageSecurityEnvironmentInstance();
        ApduCommand acPerformSecurityOperation = acPerformSecurityOperationInstance();
        ParamReference param = new ParamReference();
        
        try {

            lastSW = getPkcs15PrivateKeyInfo(param);
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            DnieP15Decoder dec = (DnieP15Decoder) param.getValue();
            
            DnieP15Record rec = null;
            Iterator<String> iterator = dec.getLabels();
            while (iterator.hasNext()){
                String label = iterator.next();
                DnieP15Record recAux = dec.get(label);
                if (recAux.getCkaId().equals(keyId)){
                    rec = recAux;
                    break;
                }
            }
            if (rec == null){
                throw new DnieKeyNotFoundException("id not found in card");
            }
            
            path = rec.getPath();
            
            secData[3] = path[path.length-1];

            acManageSecurityEnvironment.setP1P2((byte)0x41,(byte)0xb6);
            acManageSecurityEnvironment.setData(secData);
            acManageSecurityEnvironment.exec(secureChannel);

            acPerformSecurityOperation.setP1P2((byte)0x9e,(byte)0x9a);
            acPerformSecurityOperation.setData(asn1DigestInfo);
            byte [] signature = acPerformSecurityOperation.exec(secureChannel);

            outSignature.setValue(signature);

            return lastSW;
        } finally{
            Arrays.fill(secData,NULL_BYTE);
            if (path != null) Arrays.fill(path,NULL_BYTE);
        }
     }
    public int getPkcs15PrivateKeyInfo(ParamReference outPkcs15) throws CardException,InvalidCardException{
        SecureByteBuffer buffer = new SecureByteBuffer();
        CardChannel channel = card.getSecureChannel();
        if (channel == null){
            channel = card.getCardChannel();
        }
        byte [] result = null;
        int lastSW;
        ApduCommand acSelectFile = acSelectFileInstance();
        ApduCommand acGetBinary = acGetBinaryInstance();
        try {
            acSelectFile.setP1P2((byte)0x04, (byte)0x00);
            acSelectFile.setData(masterFile); 
            acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            
            acSelectFile.setP1P2((byte)0x00, (byte)0x00);
            acSelectFile.setData(new byte[]{0x50,0x15});
            acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            
            acSelectFile.setP1P2((byte)0x00, (byte)0x00);
            acSelectFile.setData(new byte[]{0x60,0x01});
            result = acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK){
                return lastSW;
            }


            int bytes = (result[7] << 8 ) | result[8];
            for (int off = 0;off < bytes;){
                acGetBinary.setP1P2((byte)(off >> 8),(byte)(off & 0x0ff));
                if ((bytes - off) < 0x0ef){
                    acGetBinary.setLe((byte)(bytes - off));
                } else {
                    acGetBinary.setLe((byte)0x0ef);
                }

                off=off+0x0ef;

                result = acGetBinary.exec(channel);
                lastSW = acGetBinary.getLastSw();
                if (lastSW != ApduCommand.SW_OK){
                    return lastSW;
                }
                buffer.write(result);

            }
            DnieP15Decoder dec = new DnieP15Decoder();
            dec.decode(buffer.getByteArray());        
            
            outPkcs15.setValue(dec);
            return lastSW;
        } finally{
            if (result != null) Arrays.fill(result,NULL_BYTE);
            buffer.clear();
        }
            
    }
    public int getPkcs15CertificateInfo(ParamReference outPkcs15) throws CardException ,InvalidCardException{

        ApduCommand acSelectFile = acSelectFileInstance();
        ApduCommand acgetBinary = acGetBinaryInstance();
        SecureByteBuffer buffer = new SecureByteBuffer();
        
        CardChannel channel = card.getSecureChannel();
        if (channel == null){
            channel = card.getCardChannel();
        }
        
        int lastSW;
        byte [] result = null;
        
        try {
                
            acSelectFile.setP1P2((byte)0x04, (byte)0x00);
            acSelectFile.setData(masterFile); 
            acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            acSelectFile.setP1P2((byte)0x00, (byte)0x00);
            acSelectFile.setData(new byte[]{0x50,0x15});
            acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            acSelectFile.setP1P2((byte)0x00, (byte)0x00);
            acSelectFile.setData(new byte[]{0x60,0x04});
            result = acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
        
        
            int bytes = (result[7] << 8 ) | result[8];
            for (int off = 0;off < bytes;){
                acgetBinary.setP1P2((byte)(off >> 8),(byte)(off & 0x0ff));
                int rest = bytes - off;
                if (rest < 0x0ef){
                    acgetBinary.setLe((byte)rest);
                } else {
                    acgetBinary.setLe((byte)0x0ef);
                }

                result = acgetBinary.exec(channel);
                if (acgetBinary.getLastSw1() == (byte)0x6c){
                    bytes = bytes + (acgetBinary.getLastSw2() & 0x0ff) - rest;
                    continue;
                }
                lastSW = acgetBinary.getLastSw();
                if (lastSW != ApduCommand.SW_OK){
                    return lastSW;
                }
                buffer.write(result);
                off=off+0x0ef;

            }
            DnieP15Decoder dec = new DnieP15Decoder();
            dec.decode(buffer.getByteArray());   
            outPkcs15.setValue(dec);
            return lastSW;
        } finally {
            Arrays.asList(result,NULL_BYTE);
            buffer.clear();
        }
        
        
    }
    
    public int getCertificate(byte [] path,ParamReference param) throws CardException,InvalidCardException{
        byte[] result = null;
        SecureByteBuffer buffer = new SecureByteBuffer();
        CardChannel secureChannel = card.getSecureChannel();
        
        ApduCommand acSelectFile = acSelectFileInstance();
        ApduCommand acGetBinary = acGetBinaryInstance();
        int lastSW;
        
        try {
            acSelectFile.setP1P2((byte)0x04, (byte)0x00);
            acSelectFile.setData(masterFile); 
            acSelectFile.exec(secureChannel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            acSelectFile.setP1P2((byte)0x00, (byte)0x00);
            acSelectFile.setData(new byte[]{path[0],path[1]});
            acSelectFile.exec(secureChannel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;

            acSelectFile.setP1P2((byte)0x00, (byte)0x00);
            acSelectFile.setData(new byte[]{path[2],path[3]});
            result = acSelectFile.exec(secureChannel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            
            int bytes = (result[7] << 8 ) | result[8];
            for (int off = 0;off < bytes;){
                acGetBinary.setP1P2((byte)(off >> 8),(byte)(off & 0x0ff));
                int rest = bytes - off;
                if (rest < 0x0ef){
                    acGetBinary.setLe((byte)rest);
                } else {
                    acGetBinary.setLe((byte)0x0ef);
                }


                result = acGetBinary.exec(secureChannel);
                if (acGetBinary.getLastSw1() == (byte)0x6c){
                    bytes = bytes + (acGetBinary.getLastSw2() & 0x0ff) - rest;
                    continue;
                }
                lastSW = acGetBinary.getLastSw();
                if (lastSW != ApduCommand.SW_OK){
                    return lastSW;
                }
                buffer.write(result);
                off=off+0x0ef;

            }
            param.setValue(buffer.getByteArray());
            return lastSW;

        } finally{
            Arrays.asList(result,NULL_BYTE);
            buffer.clear();
        }        
    }
    
    

    
    
    
    private ApduCommand acVerifyInstance(){
        return new ApduCommand("VERIFY",(byte)0x00,(byte)0x20,(byte)0x00,(byte)0x00);
    }
    private static ApduCommand acChipInfoInstance(){
        return new ApduCommand("GET CHIP INFO",(byte)0x90,(byte)0xB8,(byte)0x00,(byte)0x00,(byte)0x07);
    }
    private ApduCommand acSelectFileInstance(){
        return new ApduCommand("SELECT FILE",(byte)0x00,(byte)0xA4,(byte)0x00,(byte)0x00);
    }

    public static ApduCommand acGetResponseInstance(){
        return new ApduCommand("GET_RESPONSE",(byte)0x00,(byte)0xC0,(byte)0x00,(byte)0x00);
    }
    private ApduCommand acGetBinaryInstance(){
        return new ApduCommand("GET BINARY",(byte)0x00,(byte)0xB0,(byte)0x00,(byte)0x00);
    }
    private ApduCommand acManageSecurityEnvironmentInstance(){
        return new ApduCommand("MANAGE SEC ENVIRON",(byte)0x00,(byte)0x22);
    }
    private ApduCommand acPerformSecurityOperationInstance(){
        return new ApduCommand("PERF SEC OPER",(byte)0x00,(byte)0x2a);
    }
    
    private ApduCommand acInternalAuthenticationInstance(){
        return new ApduCommand("INTERNAL AUTH",(byte)0x00,(byte)0x88,(byte)0x00,(byte)0x00);
    }
    private ApduCommand acExternalAuthenticationInstance(){
        return new ApduCommand("EXTERNAL AUTH",(byte)0x00,(byte)0x82,(byte)0x00,(byte)0x00);
    }
    
    private ApduCommand acGetChallengeInstance(){
        return new ApduCommand("GET CHALLENGE",(byte)0x00,(byte)0x84,(byte)0x00,(byte)0x00,(byte)0x08);
    }
    
    private ApduCommand acGetComponentCertificate(){
        return new DnieGetFileContent("GET COMPONENT",new byte[]{0x60,0x1F});
    }
    private ApduCommand acGetCAComponentCertificate(){
        return new DnieGetFileContent("GET CA COMPONENT", new byte[]{0x60,0x20});
    }
    private ApduCommand acDniLoadCerts(){
        return new DniLoadCerts();
    }
    
    private int doCheckCertificate(CardChannel channel, ParamReference iccPubkey) throws
            DnieGettingCryptoProviderExcetion,DnieUnexpectedException,CardException{
        
        ApduCommand acSelectFile = acSelectFileInstance();
        ApduCommand acGetComponentCertificate = acGetComponentCertificate();
        ApduCommand acGetCAComponentCertificate = acGetCAComponentCertificate();
        byte[] componentCertificate = null;
        X509Certificate componentX509Certificate = null;

        byte[] caComponentCertificate = null;
        X509Certificate caComponentX509Certificate = null;
        int lastSW;

        try{
            // Get ICC cert
            // go root
            acSelectFile.setP1P2((byte)0x04, (byte)0x00);
            acSelectFile.setData(masterFile); 
            acSelectFile.exec(channel);
            lastSW = acSelectFile.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            
            componentCertificate = acGetComponentCertificate.exec(channel);
            lastSW = acGetComponentCertificate.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            componentX509Certificate = X509Certificate.getInstance(componentCertificate);
            // Get ICC CA cert
            caComponentCertificate = acGetCAComponentCertificate.exec(channel);
            lastSW = acGetCAComponentCertificate.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            caComponentX509Certificate = X509Certificate.getInstance(caComponentCertificate);
            // Verify certs
            caComponentX509Certificate.verify(getCaComponentPubkey());
            componentX509Certificate.verify(caComponentX509Certificate.getPublicKey()) ;         
            iccPubkey.setValue((RSAPublicKey)componentX509Certificate.getPublicKey());

            return lastSW;
        } catch (NoSuchProviderException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error checking card certificate",ex);
        } catch (NoSuchAlgorithmException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error checking card certificate",ex);
        } catch (CertificateException ex){
            throw new DnieUnexpectedException("Internal error checking card certificate",ex);
        } catch (InvalidKeyException ex){
            throw new DnieUnexpectedException("Internal error checking card certificate",ex);
        } catch (InvalidKeySpecException ex){
            throw new DnieUnexpectedException("Internal error checking card certificate",ex);
        } catch (SignatureException ex){
            throw new DnieUnexpectedException("Internal error checking card certificate",ex);
        } catch (UnsupportedEncodingException ex){
            throw new DnieUnexpectedException("Internal error checking card certificate",ex);
        } finally {
            if (componentCertificate != null) Arrays.fill(componentCertificate,NULL_BYTE);
            if (caComponentCertificate != null) Arrays.fill(caComponentCertificate,NULL_BYTE);
        }
    }
    
    private RSAPrivateKey getIfdRSAPrivateKey() throws DnieGettingCryptoProviderExcetion,
            DnieUnexpectedException{
        try {
            BigInteger ifdModulus = new BigInteger(1,IFD_MODULUS);
            BigInteger privExponent = new BigInteger(1,IFD_PRIV_EXPONENT);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(ifdModulus,privExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error getting IFD key",ex);
        } catch (InvalidKeySpecException ex){
            throw new DnieUnexpectedException("Internal error getting IFD key",ex);
        }
        
    }
    
    private int doInternalAuthentication(CardChannel channel,byte[] randomBytes,
        RSAPrivateKey ifdKey,RSAPublicKey iccPubkey,ParamReference outKicc) throws
            DnieSettingSecureChannelException,DnieGettingCryptoProviderExcetion,
            DnieUnexpectedException, CardException{
        ApduCommand acInternalAuthentication = acInternalAuthenticationInstance();
        byte [] internalAuthenticationData = null;
        byte [] decryptedData = null;
        byte [] macBytes = null;
        byte [] sub = null;
        byte [] bn = null;
        byte [] resumen1 = null;
        byte [] kicc = null;
        byte [] prnd1 = null;
        byte [] resumen2 = null;
        int lastSW;

        byte intAuthData[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        try {
            /*
             * INTERNAL AUTHENTICATION 
             */
            System.arraycopy(randomBytes, 0, intAuthData, 0, 8);
            acInternalAuthentication.setData(intAuthData);
            internalAuthenticationData = acInternalAuthentication.exec(channel);
            lastSW = acInternalAuthentication.getLastSw();
            if (lastSW != ApduCommand.SW_OK) return lastSW;
            //Decript
            

            // Get an instance of the Cipher for RSA encryption/decryption
            Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING");
            // Initiate the Cipher, telling it that it is going to Decrypt, giving it the private key
            dec.init(Cipher.DECRYPT_MODE, ifdKey);
            decryptedData = dec.doFinal(internalAuthenticationData);

            dec = Cipher.getInstance("RSA/ECB/NOPADDING");
            // Initiate the Cipher, telling it that it is going to Decrypt, giving it the private key
            dec.init(Cipher.ENCRYPT_MODE, iccPubkey);
            macBytes = dec.doFinal(decryptedData);

            if (!((macBytes[0] == (byte)0x6a) && (macBytes[macBytes.length-1] == (byte)0x0bc))){
                BigInteger sig = new BigInteger(decryptedData);
                sub = iccPubkey.getModulus().subtract(sig).toByteArray();
                bn = new byte [128];
                if ((sub.length > 128) && (sub[0] == 0x00)){
                    System.arraycopy(sub, 1, bn, 0, sub.length-1);
                } else {
                    System.arraycopy(sub, 0, bn, 0, sub.length);
                }
                dec.init(Cipher.ENCRYPT_MODE, iccPubkey);
                macBytes = dec.doFinal(bn);

            }

            if (!((macBytes[0] == (byte)0x6a) && (macBytes[macBytes.length-1] == (byte)0xbc))){
                throw new DnieSettingSecureChannelException("Error checking MACs in internal authenticacion");
            }
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            resumen1 = new byte[messageDigest.getDigestLength()];
            kicc = new byte[32];
            int tamaPrnd1 = macBytes.length-2-kicc.length-messageDigest.getDigestLength();
            prnd1 = new byte[tamaPrnd1];
            System.arraycopy(macBytes, 1, prnd1, 0, tamaPrnd1);
            System.arraycopy(macBytes, tamaPrnd1 + 1 , kicc, 0, kicc.length);
            System.arraycopy(macBytes, tamaPrnd1 + 1 + kicc.length, resumen1, 0, resumen1.length);
            messageDigest.update(prnd1);
            messageDigest.update(kicc);
            messageDigest.update(randomBytes);
            messageDigest.update(CHR_IFD);
            resumen2 = messageDigest.digest();

            if (!Arrays.equals(resumen1, resumen2)){
                throw new DnieSettingSecureChannelException("Error checking HASH in internal authenticacion");
            }     
            outKicc.setValue(Arrays.copyOf(kicc, kicc.length));
            
            return lastSW;
        } catch (NoSuchAlgorithmException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error in internal authentication",ex);
        } catch (InvalidKeyException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error in internal authentication",ex);
        } catch (NoSuchPaddingException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error in internal authentication",ex);
        } catch (IllegalBlockSizeException ex){
            throw new DnieUnexpectedException("Internal error in internal authentication",ex);
        } catch (BadPaddingException ex){
            throw new DnieUnexpectedException("Internal error in internal authentication",ex);
        } finally {
            Arrays.fill(intAuthData,NULL_BYTE);
            if (internalAuthenticationData != null) Arrays.fill(internalAuthenticationData, NULL_BYTE);
            if (decryptedData != null)  Arrays.fill(decryptedData,NULL_BYTE);
            if (macBytes != null) Arrays.fill(macBytes,NULL_BYTE);
            if (sub != null) Arrays.fill(sub,NULL_BYTE);
            if (bn != null) Arrays.fill(bn,NULL_BYTE);
            if (resumen1 != null) Arrays.fill(resumen1,NULL_BYTE);
            if (kicc != null) Arrays.fill(kicc,NULL_BYTE);
            if (prnd1 != null) Arrays.fill(prnd1,NULL_BYTE);
            if (resumen2 != null) Arrays.fill(resumen2,NULL_BYTE);                            
        }
    }
    
    private int doExternalAuthentication(CardChannel channel,byte[] serialNumber,
            byte [] challenge,RSAPrivateKey ifdKey,RSAPublicKey iccPubkey,
            ParamReference outKifd) throws DnieGettingCryptoProviderExcetion,
            DnieUnexpectedException, CardException{
        int lastSW;
        byte [] resumen = null;
        byte [] message = null;
        byte [] sig = null;
        byte [] signum = null;
        byte [] extAuthData = null;
        byte [] kifd = null;
        byte [] prnd = null;
        
        ApduCommand acExternalAuthentication = acExternalAuthenticationInstance();
        
        // get chip info
        try {

            int byteCount = IFD_MODULUS.length;
            kifd = new byte[32];
            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            prnd = new byte [byteCount-2-kifd.length-messageDigest.getDigestLength()];
            sr.nextBytes(kifd);
            sr.nextBytes(prnd);
            messageDigest.update(prnd);
            messageDigest.update(kifd);
            messageDigest.update(challenge);
            byte paddedSerialNumber[] = serialNumber;
            if (paddedSerialNumber.length < 8){
                paddedSerialNumber = new byte[8];
                paddedSerialNumber[0] = 0x00;
                System.arraycopy(serialNumber, 0, paddedSerialNumber, 1, serialNumber.length);
            }
            messageDigest.update(paddedSerialNumber);
            resumen = messageDigest.digest();

            message = new byte[1+prnd.length+kifd.length+resumen.length+1];
            message[0] = (byte)0x6a;
            message[message.length-1] = (byte)0xbc;
            System.arraycopy(prnd, 0, message, 1, prnd.length);
            System.arraycopy(kifd, 0, message, 1 + prnd.length, kifd.length);
            System.arraycopy(resumen, 0, message, 1 + prnd.length + kifd.length, resumen.length);

            Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING");
            dec.init(Cipher.DECRYPT_MODE, ifdKey);
            sig = dec.doFinal(message);

            BigInteger bnSig = new BigInteger(1,sig);
            BigInteger sub = ifdKey.getModulus().subtract(bnSig);
            BigInteger bnSignum = sub.min(bnSig);

            signum = bnSignum.toByteArray();

            dec = Cipher.getInstance("RSA/ECB/NOPADDING");
            // Initiate the Cipher, telling it that it is going to Decrypt, giving it the private key
            dec.init(Cipher.ENCRYPT_MODE, iccPubkey);
            extAuthData = dec.doFinal(signum);

            acExternalAuthentication.setData(extAuthData);
            acExternalAuthentication.exec(channel);

            lastSW = acExternalAuthentication.getLastSw();
            outKifd.setValue(Arrays.copyOf(kifd, kifd.length));
            return lastSW;        
        } catch (NoSuchAlgorithmException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error in external authentication",ex);
        } catch (NoSuchPaddingException ex){
            throw new DnieGettingCryptoProviderExcetion("Internal error in external authentication",ex);
        } catch (IllegalBlockSizeException ex){
            throw new DnieUnexpectedException("Internal error in external authentication",ex);
        } catch (BadPaddingException ex){
            throw new DnieUnexpectedException("Internal error in external authentication",ex);
        } catch (InvalidKeyException ex){
            throw new DnieUnexpectedException("Internal error getting IFD key",ex);
        } finally{
            if (resumen != null) Arrays.fill(resumen, NULL_BYTE);
            if (message != null) Arrays.fill(message, NULL_BYTE);
            if (sig != null) Arrays.fill(sig, NULL_BYTE);
            if (signum != null) Arrays.fill(signum, NULL_BYTE);
            if (extAuthData != null) Arrays.fill(extAuthData, NULL_BYTE);
            if (kifd != null) Arrays.fill(kifd, NULL_BYTE);
            if (prnd != null) Arrays.fill(prnd, NULL_BYTE);
            
        }
    }
    
    private DnieSecureChannel doSecureChannelInstance(CardChannel channel,byte[] randomBytes,
            byte[] challenge,byte[] kicc,byte[] kifd) throws DnieGettingCryptoProviderExcetion{
        byte [] xored = null;
        byte [] kifdicc = null;
        byte [] resumen1 = null;
        byte [] resumen2 = null;
        byte [] kenc = null;
        byte [] kmac = null;
        byte [] scc = null;
        
        try {
    
            BigInteger bnKicc = new BigInteger(1,kicc);
            BigInteger bnKifd = new BigInteger(1,kifd);
            xored = bnKicc.xor(bnKifd).toByteArray();
            kifdicc = new byte[kicc.length];
            System.arraycopy(xored,xored.length-kifdicc.length,kifdicc,0,kifdicc.length);

            MessageDigest messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(kifdicc);
            messageDigest.update(ApduCommand.fromHexString("00000001"));
            resumen1 = messageDigest.digest();
            kenc = new byte[16];
            System.arraycopy(resumen1, 0, kenc, 0, kenc.length);

            messageDigest = MessageDigest.getInstance("SHA");
            messageDigest.update(kifdicc);
            messageDigest.update(ApduCommand.fromHexString("00000002"));
            resumen2 = messageDigest.digest();
            kmac = new byte[16];
            System.arraycopy(resumen2, 0, kmac, 0, kmac.length);

            scc = new byte[8];
            System.arraycopy(challenge, 4, scc, 0, 4);
            System.arraycopy(randomBytes, 4, scc, 4, 4);

            return new DnieSecureChannel(channel,kenc,kmac,scc);         
        } catch (NoSuchAlgorithmException ex){
            if(kenc != null) Arrays.fill(kenc,NULL_BYTE);
            if(kmac != null) Arrays.fill(kmac,NULL_BYTE);
            if(scc != null) Arrays.fill(scc,NULL_BYTE);
            throw new DnieGettingCryptoProviderExcetion("Error instancing secure channel",ex);
            
        } finally {
            if(xored != null) Arrays.fill(xored,NULL_BYTE);
            if(kifdicc != null) Arrays.fill(kifdicc,NULL_BYTE);
            if(resumen1 != null) Arrays.fill(resumen1,NULL_BYTE);
            if(resumen2 != null) Arrays.fill(resumen2,NULL_BYTE);
            
        }
        
        
        
    }
    

    
    private final class DnieGetFileContent  extends ApduCommand{
        private byte file[];
        public DnieGetFileContent(byte file[]){
            this.file = file;
        }
        public DnieGetFileContent(String name,byte file[]){
            this(file);
            this.name = name;
        }
        @Override
        public byte [] exec(CardChannel channel) throws CardException{
            ApduCommand selectFile = acSelectFileInstance();
            ApduCommand getResponse = acGetResponseInstance();
            ApduCommand getBinary = acGetBinaryInstance();
            selectFile.setData(file);
            byte b[] = selectFile.exec(channel);
            lastSW = selectFile.getLastSw();
            if (getLastSw1() == 0x61){
                byte len = selectFile.getLastSw2();
                getResponse.setLe(len);
                b = getResponse.exec(channel);
                lastSW = getResponse.getLastSw();
            }

            if (lastSW == SW_OK){
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    int bytes = (b[7] << 8 ) | b[8];
                    for (int off = 0;off < bytes;off=off+0x0ff){
                        getBinary.setP1P2((byte)(off >> 8),(byte)(off & 0x0ff));
                        if ((bytes - off) < 0x0ff){
                            getBinary.setLe((byte)(bytes - off));
                        } else {
                            getBinary.setLe((byte)0x0ff);
                        }
                        b = getBinary.exec(channel);
                        lastSW = getBinary.getLastSw();
                        if (lastSW != SW_OK){
                            return null;
                        }
                        baos.write(b);
                    }
                    baos.close();
                    return baos.toByteArray();
                } catch (IOException ex){
                    throw new CardException(ex);
                }
            } else {
                return null;
            }
        }        

    }
    
    private final class DniLoadCerts extends ApduCommand {
        
        private byte mseP1 = (byte)0x81;
        private byte mseP2 = (byte)0xb6;
        private byte mseCaData[] = {
            (byte)0x83,(byte)0x02,(byte)0x02,(byte)0x0f};
        //CHR = 000000006573534449600006
        private byte mseChr6573[] = {
            (byte)0x83,(byte)0x08,(byte)0x65,(byte)0x73,
            (byte)0x53,(byte)0x44,(byte)0x49,(byte)0x60,
            (byte)0x00,(byte)0x06};
        
        
        private byte pubKeySelP1 = (byte)0xc1;
        private byte pubKeySelP2 = (byte)0xa4;
        //CHR = 000000002000000000000001
        private byte mseChr0000[] = {
            (byte)0x84,(byte)0x02,(byte)0x02,(byte)0x1f,
            (byte)0x83,(byte)0x0c,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x20,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x01};

        
        private byte psoP1 = (byte)0x00;
        private byte psoP2 = (byte)0xae;
        
        @Override
        public byte [] exec(CardChannel channel) throws CardException{        
            ApduCommand manageSecurityEnvironment = acManageSecurityEnvironmentInstance();
            ApduCommand performSecurityOperation = acPerformSecurityOperationInstance();
            
            manageSecurityEnvironment.setP1P2(mseP1, mseP2);
            manageSecurityEnvironment.setData(mseCaData);
            manageSecurityEnvironment.exec(channel);
            lastSW = manageSecurityEnvironment.getLastSw();
            if (lastSW != SW_OK) return null;
            
            performSecurityOperation.setP1P2(psoP1, psoP2);
            performSecurityOperation.setData(C_CV_CA);
            performSecurityOperation.exec(channel);
            if (lastSW != SW_OK) return null;
            
            manageSecurityEnvironment.reset();
            manageSecurityEnvironment.setP1P2(mseP1, mseP2);
            manageSecurityEnvironment.setData(mseChr6573);
            manageSecurityEnvironment.exec(channel);
            lastSW = manageSecurityEnvironment.getLastSw();
            if (lastSW != SW_OK) return null;
            
            performSecurityOperation.reset();
            performSecurityOperation.setP1P2(psoP1, psoP2);
            performSecurityOperation.setData(C_CV_IFD);
            performSecurityOperation.exec(channel);
            if (lastSW != SW_OK) return null;

            manageSecurityEnvironment.reset();
            manageSecurityEnvironment.setP1P2(pubKeySelP1, pubKeySelP2);
            manageSecurityEnvironment.setData(mseChr0000);
            manageSecurityEnvironment.exec(channel);
            lastSW = manageSecurityEnvironment.getLastSw();
            if (lastSW != SW_OK) return null;

            return null;
        }
 
    };    
    public static PublicKey getCaComponentPubkey() throws NoSuchAlgorithmException,InvalidKeySpecException,UnsupportedEncodingException{

        BigInteger modulus = new BigInteger(1, CA_COMPONENT_MODULUS);
        BigInteger exponent = new BigInteger(1, CA_COMPONENT_EXPONENT);
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(publicKeySpec);
    }       

}
