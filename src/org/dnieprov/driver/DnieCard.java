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
package org.dnieprov.driver;

import java.util.Iterator;

/**
 * Wrapper for DnieCardImpl (maybe this is not necesary)
 * @author luis
 * 
 */
public class DnieCard {
    private final DnieCardImpl cardImpl;
    /**
     * 
     * @param cardImpl Real DnieCard Object
     */
    public DnieCard (DnieCardImpl cardImpl){
        this.cardImpl = cardImpl;
    }
    /**
     * 
     * @return return wrapped object
     */
    public DnieCardImpl getCardImpl(){
        return cardImpl;
    }
    /**
     * 
     * @return on card removal, this card object would be invalid
     */
    public boolean isValid(){
        return cardImpl.isValid();
    }
    /**
     * 
     * @param subject subject dn 
     * @return true if this card holds certificate with same subject dn
     */
    public boolean hasSubject(String subject){
        return cardImpl.hasSubject(subject);
    }
    /**
     * 
     * @return get PKCS15 public info for this card
     */
    public Iterator<DnieP15Record> getInfo(){
        return cardImpl.getInfo();
    }
    

}