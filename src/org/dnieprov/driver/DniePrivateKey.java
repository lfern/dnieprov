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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Private Key representation for DNIe cert.
 * @author luis
 */
public class DniePrivateKey implements RSAPrivateKey{
    private final X509Certificate cert;
    private final DnieSession session;

    
    public DniePrivateKey(DnieSession session,X509Certificate cert){
        this.cert = cert;
        this.session = session;
    }

    @Override
    public BigInteger getModulus() {
        return ((RSAPublicKey)cert.getPublicKey()).getModulus();
    }

    @Override
    public BigInteger getPrivateExponent() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getAlgorithm() {
        return cert.getPublicKey().getAlgorithm();
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getFormat() {
        
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public boolean inCard(DnieCard card){
        return session.getCard().getCardImpl().equals(card.getCardImpl());
    }
    
    public X509Certificate getCertificate(){
        return cert;
    }
    
    public DnieSession getSession(){
        return session;
    }
    
}
