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
 *   Solo podrá usarse esta obra su se respeta la Licencia.
 *   Puede obtenerse una copia de la Licencia en:
 *   http://ec.europa.eu/idabc/eupl 
 *   El programa distribuido con arreglo a la Licencia se distribuye "TAL CUAL",
 *   SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * ----------------------------------------------------------------------* 
 */
package org.dnieprov.driver.utils;

import org.dnieprov.driver.utils.bertlv.BerTlv;
import org.dnieprov.driver.utils.bertlv.BerTlvIdentifier;
import org.dnieprov.driver.utils.bertlv.BerType;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import sun.security.x509.AlgorithmId;

/**
 *
 * @author luis
 */
public class DigestInfo {
    public static byte[] encode(String digestAlgorithm,byte[] digest) throws NoSuchAlgorithmException,IOException{
        /*
        BerTlv algId = new BerTlv();
        algId.setTag(new BerTlvIdentifier(BerType.SEQUENCE));
        algId.setValue(AlgorithmId.get(digestAlgorithm).encode());
        */
        BerTlv dig = new BerTlv();
        dig.setTag(new BerTlvIdentifier(BerType.OCTET_STRING));
        dig.setValue(digest);
        
        BerTlv di = new BerTlv();
        di.setTag(new BerTlvIdentifier(BerType.SEQUENCE));
        di.setValue(ByteArrayUtils.concat(AlgorithmId.get(digestAlgorithm).encode(),dig.getBytes()));
        return di.getBytes();
    }
}
