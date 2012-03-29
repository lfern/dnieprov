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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import org.dnieprov.crypto.Digest;
import org.dnieprov.crypto.digests.SHA1Digest;
import org.dnieprov.crypto.digests.SHA256Digest;
import org.dnieprov.crypto.digests.SHA384Digest;
import org.dnieprov.crypto.digests.SHA512Digest;
import org.dnieprov.driver.DnieCard;
import org.dnieprov.driver.DnieDriver;
import org.dnieprov.driver.DniePrivateKey;
import org.dnieprov.driver.exceptions.DnieDriverException;
import org.dnieprov.driver.exceptions.DnieDriverPinException;
import org.dnieprov.driver.exceptions.InvalidCardException;

/**
 * Implementation of signature engine for DNIe.
 * @author luis
 */
public class DnieSignature extends SignatureSpi {

    private Digest digest;
    private final DnieDriver driver;
    
    private DniePrivateKey dnieKey = null;

    
    protected DnieSignature(DnieDriver driver,Digest digest) {
        this.digest = digest;
        this.driver = driver;
    }
    
    @Override
    protected void finalize() throws Throwable {
      super.finalize();
    } 

    /**
     * @deprecated
     */
    @Override
    protected Object engineGetParameter(
        String      param)
    {
        return null;
    }
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }
    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
     */
    @Override
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
    
    @Override
    protected void engineUpdate(byte[] b,int off,int len) throws SignatureException {
        digest.update(b,off,len);
    }
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        digest.update(b);
    }
    
    @Override
    protected void engineInitSign(PrivateKey  privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof DniePrivateKey)){
            throw new InvalidKeyException("Key not found in driver");
        }
        DniePrivateKey tmpDnieKey = (DniePrivateKey)privateKey;
        
        Enumeration<DnieCard> cards = driver.getCards();
        boolean found = false;
        while (cards.hasMoreElements()){
            DnieCard card = cards.nextElement();
            if (tmpDnieKey.inCard(card)){
                found = true;
                this.dnieKey = tmpDnieKey;
            }
        }
        if (!found){
            throw new InvalidKeyException("Key not found in driver");
        }
    }
    @Override
    protected byte[] engineSign()
        throws SignatureException{
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);
        
        String algorithm = digest.getAlgorithmName();
        try {
            return driver.sign(this.dnieKey.getSession(),algorithm,hash,dnieKey.getCertificate());
        } catch (DnieDriverException ex){
            throw new SignatureException(ex);
        } catch (NoSuchAlgorithmException ex){
            throw new SignatureException(ex);
        } catch (DnieDriverPinException ex){
            throw new SignatureException(ex);
        } catch (InvalidCardException ex){
            throw new SignatureException(ex);
        }
    }
    
    @Override
    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException("engineVerify unsupported");
    }
    
    static public class SHA1WithRSAEncryption
        extends DnieSignature
    {
        public SHA1WithRSAEncryption(DnieDriver driver)
        {
            super(driver,new SHA1Digest());
        }
    }

    static public class SHA256WithRSAEncryption
        extends DnieSignature
    {
        public SHA256WithRSAEncryption(DnieDriver driver)
        {
            super(driver,new SHA256Digest());
        }
    }

    static public class SHA384WithRSAEncryption
        extends DnieSignature
    {
        public SHA384WithRSAEncryption(DnieDriver driver)
        {
            super(driver,new SHA384Digest());
        }
    }

    static public class SHA512WithRSAEncryption
        extends DnieSignature
    {
        public SHA512WithRSAEncryption(DnieDriver driver)
        {
            super(driver,new SHA512Digest());
        }
    }    
    
}
