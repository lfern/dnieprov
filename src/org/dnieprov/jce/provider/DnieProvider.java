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

import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Arrays;
import java.util.List;
import org.dnieprov.driver.DnieDriver;
import org.dnieprov.driver.exceptions.DnieDriverException;

/**
 * Cryptographic Service Provider for DNIe.
 * @author luis
 */
public class DnieProvider extends Provider {
    
    private static final String INFO = "DNIe Provider v1.2";
    private static final double VERSION = 1.2;

    private static final String PROVIDER_NAME = "DNIeProv";
    private static final String DNIE_ALG = "DNIe";
    
    private static final String KS = "KeyStore";
    private static final String SIG = "Signature";
    
    private static final String SHA1_RSA   = "SHA1withRSA";
    private static final String SHA256_RSA = "SHA-256withRSA";
    private static final String SHA384_RSA = "SHA-384withRSA";
    private static final String SHA512_RSA = "SHA-512withRSA";

    private static final String SHA256_RSA_ALIAS = "SHA256withRSA";
    private static final String SHA384_RSA_ALIAS = "SHA384withRSA";
    private static final String SHA512_RSA_ALIAS = "SHA512withRSA";
    
    
    public DnieProvider()  {
        super(PROVIDER_NAME, VERSION, INFO);

        AccessController.doPrivileged(new PrivilegedAction()
        {
            @Override
            public Object run()
            {
                setup();
                return null;
            }
        });
    }    
    
    private void setup(){
        // KeyStore service
        putService(new DnieService(this,KS,DNIE_ALG,"org.dnieprov.jce.provider.DnieKeyStore",s(DNIE_ALG)));
        
        // Signature Service
        putService(new DnieService(this,SIG,SHA1_RSA,"org.dnieprov.jce.provider.DnieDigestSignature$SHA1WithRSAEncryption",s(SHA1_RSA)));
        putService(new DnieService(this,SIG,SHA256_RSA,"org.dnieprov.jce.provider.DnieDigestSignature$SHA256WithRSAEncryption",s(SHA256_RSA_ALIAS)));
        putService(new DnieService(this,SIG,SHA384_RSA,"org.dnieprov.jce.provider.DnieDigestSignature$SHA384WithRSAEncryption",s(SHA384_RSA_ALIAS)));
        putService(new DnieService(this,SIG,SHA512_RSA,"org.dnieprov.jce.provider.DnieDigestSignature$SHA512WithRSAEncryption",s(SHA512_RSA_ALIAS)));
        
    }
    private static final class DnieService extends Service {
         private static final DnieDriver driver = new DnieDriver();
         DnieService(Provider prov,String type,String algorithm,String className,String[] al){
             super(prov, type, algorithm, className,toList(al), null);
             try {
                driver.init();
             } catch (DnieDriverException ex){
                 
             }
         }
        private static List<String> toList(String[] aliases) {
            return (aliases == null) ? null : Arrays.asList(aliases);
        }
        @Override
        public Object newInstance(Object param)
                throws NoSuchAlgorithmException {
            return newInstance0(param);
        }

        public Object newInstance0(Object param)
                throws NoSuchAlgorithmException {
            String algorithm = getAlgorithm();
            String type = getType();
            if (type.equals(SIG)) {
                if (algorithm.equals(SHA1_RSA)){
                    return new DnieSignature.SHA1WithRSAEncryption(driver);
                } else if (algorithm.equals(SHA256_RSA)){
                    return new DnieSignature.SHA256WithRSAEncryption(driver);
                } else if (algorithm.equals(SHA384_RSA)){
                    return new DnieSignature.SHA384WithRSAEncryption(driver);
                } else if (algorithm.equals(SHA512_RSA)){
                    return new DnieSignature.SHA512WithRSAEncryption(driver);
                } else {
                    throw new NoSuchAlgorithmException("Unknown algorithm: " + algorithm);
                }
            } else if (type.equals(KS)) {
                return new DnieKeyStore(driver);
            } else {
                throw new NoSuchAlgorithmException("Unknown type: " + type);
            }
        }        
         
    }
    private static String[] s(String s1) {
        return new String[] { s1 };
    }    
}
