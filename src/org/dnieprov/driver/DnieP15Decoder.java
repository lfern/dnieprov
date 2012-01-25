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

import org.dnieprov.driver.utils.bertlv.BerTlv;
import org.dnieprov.driver.utils.bertlv.BerType;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Simple PKCS15 decoder
 * @author luis
 */

/** TODO: This only gets label, path and id parameters. */
class DnieP15Decoder {
    
    private HashMap map;
    
    public DnieP15Decoder(){
        map = new HashMap();
    }
    
    public DnieP15Record get(String label){
        return (DnieP15Record) map.get(label);
    }
    public Iterator<String> getLabels(){
        return map.keySet().iterator();
    }
    
    public void decode(byte buffer[]){
        
        ByteArrayInputStream bais1 = new ByteArrayInputStream(buffer);
        
        while (bais1.available()>0){
            BerTlv seq = new BerTlv();
            try {
                seq.decode(bais1);
            } catch (Exception ex){
                return;
            }
            if (seq.getTag().getTagValue() == BerType.SEQUENCE){
                BerTlv record = new BerTlv();

                ByteArrayInputStream bais2 = new ByteArrayInputStream(seq.getValue());
                record.decode(bais2);
                BerTlv str = new BerTlv();
                str.decode(record.getValue());
                String ckaLabel = new String(str.getValue());
                
                record.decode(bais2);
                str.decode(record.getValue());
                String ckaId = new String(str.getValue());
                
                record.decode(bais2);
                str.decode(record.getValue());
                str.decode(str.getValue());
                str.decode(str.getValue());
                byte path [] = str.getValue();
                
                map.put(ckaLabel, new DnieP15Record(ckaLabel, ckaId, path));
            }

        }

    }
    
}
