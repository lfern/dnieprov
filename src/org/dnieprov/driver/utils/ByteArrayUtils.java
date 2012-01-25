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
package org.dnieprov.driver.utils;

import java.math.BigInteger;

/**
 *
 * @author luis
 */
public class ByteArrayUtils {
    
    private static BigInteger big1 = new BigInteger("1");
    
    public static byte[] removePadding7816(byte buf[]){
        int i = buf.length-1;
        byte lastByte = buf[i];
        if ((lastByte == (byte)0x00) || (lastByte == (byte)0x80)){
            for (;i>=0;i--){
                if (buf[i] == (byte)0x80)
                    break;
                if (buf[i] != (byte)0x00)
                    return buf;
            }
        }
        return subArray(buf, 0, i);
    }
    public static byte[] padding7816(byte[]buf,int len){
        byte dataTmp[] = new byte[(((len)/8)+1)*8];
        System.arraycopy(buf, 0, dataTmp, 0, len);
        dataTmp[len] = (byte)0x80;
        for(int i=len+1;i<dataTmp.length;i++){
            dataTmp[i] = (byte)0x00;
        }
        return dataTmp;
    }
    public static byte[] padding7816(byte[]buf){
        return padding7816(buf,buf.length);
    }
    public static byte[] padding7816(byte cla,byte ins, byte p1, byte p2){
        byte tmp [] = new byte[4];
        tmp[0] = cla;
        tmp[1] = ins;
        tmp[2] = p1;
        tmp[3] = p2;
        return padding7816(tmp, tmp.length);
    }
    public static byte[] concat(byte[] a1,byte[] a2){
        byte tmp[] = new byte[a1.length+a2.length];
        System.arraycopy(a1, 0, tmp, 0, a1.length);
        System.arraycopy(a2, 0, tmp, a1.length,a2.length);
        return tmp;
    }
    public static byte[] prepend(byte a1,byte a2[]){
        byte tmp[] = new byte[a2.length+1];
        tmp[0] = a1;
        System.arraycopy(a2, 0, tmp, 1, a2.length);
        return tmp;
        
    }
    public static byte[] concat(byte[] a1,byte a2,byte a3){
        byte tmp[];
        int len;
        if (a1 == null){
            tmp = new byte[2];
            len = 0;
        } else {
            len = a1.length;
            tmp = new byte[len+2];
            System.arraycopy(a1, 0, tmp, 0, len);
        }
        tmp[len] = a2;
        tmp[len+1] = a3;
        return tmp;
    }

    public static byte[] xor(byte a[],byte b[]){
        BigInteger bna = new BigInteger(1,a);
        BigInteger bnb = new BigInteger(1,b);
        
        byte r[] = bna.xor(bnb).toByteArray();
        if (r.length > 8){
            r = subArray(r, 1, 8);
        }
        byte res[] = new byte[a.length];
        for (int i=0;i<res.length;i++)
            res[i] = 0;
        System.arraycopy(r, 0, res, a.length-r.length, r.length);
        return res;
    }
    
    public static byte[] increment(byte buf[]){
        BigInteger t = new BigInteger(1,buf);
        t = t.add(big1);
        byte tmp[] = t.toByteArray();
        return tmp;
    }
    public static byte[] subArray(byte a[],int offset,int len){
        byte sub[] = new byte[len];
        System.arraycopy(a, offset, sub, 0, len);
        return sub;
    }    
}
