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
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Send APDU commands to the DNIe CardChannel, handling GET RESPONSE commands
 * @author luis
 */
    /*    
    * CLA : Byte de clase
    * INS : Byte de instrucción
    * P1,P2: Parámetros
    * Lc : tamaño del bloque de datos
    * Bloque de datos
    * Le : Tamaño de la respuesta esperada
    */    

class ApduCommand {
    
    protected String name = "ApduCommand";
    /** class byte */
    protected byte cla;
    /** instruction byte */
    protected byte ins;
    /** paramater byte P1 */
    protected byte p1;
    /** paramater byte P2 */
    protected byte p2;
    private byte origP1;
    private byte origP2;
    /** parameter data (optional)*/
    protected byte [] data;
    /** parameter le (optional)*/
    protected byte [] le;
    protected byte [] origLe;
    public static final byte [] EMPTY = new byte[0];
    
    public static final int SW_OK = 0x9000;
    protected int lastSW = SW_OK;
    
    public ApduCommand(){
        
    }

    public ApduCommand(String name){
        this.name = name;
        
    }
    
    public ApduCommand(byte cla, byte ins){
        this.cla = cla;
        this.ins = ins;
        this.p1  = 0;
        this.p2  = 0;
        this.origP1 = this.p1;
        this.origP2 = this.p2;
        this.data = EMPTY;
        this.le = EMPTY;
        this.origLe = EMPTY;
            
    }
    public ApduCommand(String name,byte cla, byte ins){
        this(cla,ins);
        this.name = name;
    
    }
    

    public ApduCommand(byte cla, byte ins, byte p1, byte p2){
        this.cla = cla;
        this.ins = ins;
        this.p1  = p1;
        this.p2  = p2;
        this.origP1 = this.p1;
        this.origP2 = this.p2;
        this.data = EMPTY;
        this.le = EMPTY;
        this.origLe = EMPTY;
            
    }
    public ApduCommand(String name,byte cla, byte ins, byte p1, byte p2){
        this(cla,ins,p1,p2);
        this.name = name;
    }

    public ApduCommand(byte cla, byte ins, byte p1, byte p2, byte le){
        
        this(cla,ins,p1,p2);
        this.le = new byte[1];
        this.le[0] = le;
        this.origLe = this.le;
    }
    public ApduCommand(String name,byte cla, byte ins, byte p1, byte p2, byte le){
        this(cla,ins,p1,p2,le);
        this.name = name;
    }
    
    public void setData(byte[]data){
        if (data.length > 0){
            this.data = (byte[])data.clone();
        }
    }
    
    public void reset(){
        this.data = EMPTY;
        this.le = this.origLe;
        this.p1 = this.origP1;
        this.p2 = this.origP2;
    }
    public void setLe(byte le){
        this.le = new byte[1];
        this.le[0] = le;
    }
    public void setP1P2(byte p1,byte p2){
        this.p1 = p1;
        this.p2 = p2;
    }
    
    public byte [] exec(CardChannel channel) throws CardException{
        CommandAPDU command = getCommand();
        command.getBytes();
        ApduCommand acGetResponse = DnieInterface.acGetResponseInstance();

        //Logger logger = Logger.getLogger("Dnie");
        //logger.log(Level.INFO,  "{0} >>> {1}" , new Object[]{name,ApduCommand.toString(command.getBytes())});

        ResponseAPDU r = channel.transmit(command);
        
        byte returnBytes[] = r.getData();

        //logger.log(Level.INFO,  "{0} <<< {1}" , new Object[]{name,ApduCommand.toString(r.getBytes())});
        lastSW = r.getSW();
        /** Send GET RESPONSE command to get real return result */
        if (getLastSw1() == 0x61){
            byte len = getLastSw2();
            acGetResponse.setLe(len);
            byte b[] = acGetResponse.exec(channel);
            lastSW = acGetResponse.getLastSw();
            if (returnBytes != null){
                return ByteArrayUtils.concat(returnBytes, b);
            }
            return b;
        }
        
        
        reset();
        if (lastSW != SW_OK) return null;
        
        return returnBytes;
    }
    
    public int getLastSw(){
        return lastSW;
    }
    
    public byte getLastSw1(){
        return (byte)(lastSW >> 8);
    }
    
    public byte getLastSw2(){
        return (byte)(lastSW & 0x0ff);
    }
    
    public CommandAPDU getCommand(){
        int dataL = data.length > 0 ? data.length + 1: 0;
        byte []apdu = new byte[4+le.length+dataL];
        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        if (dataL > 0){
            apdu[4] = (byte)data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
            System.arraycopy(le, 0, apdu, 5+data.length, le.length);
        } else {
            System.arraycopy(le, 0, apdu, 4, le.length);
        }
        
        return new CommandAPDU(apdu);
    }
    public static String toString(byte[] bytes) {

        final String hexChars = "0123456789ABCDEF";
        StringBuilder sbTmp = new StringBuilder();
        char[] cTmp = new char[2];

        for (int i = 0; i < bytes.length; i++) {
            cTmp[0] = hexChars.charAt((bytes[i] & 0xF0) >>> 4);
            cTmp[1] = hexChars.charAt(bytes[i] & 0x0F);
            sbTmp.append(cTmp);
        }

        return sbTmp.toString();
    }    
    public static String toString(byte b) {

        final String hexChars = "0123456789ABCDEF";
        StringBuilder sbTmp = new StringBuilder();
        char[] cTmp = new char[2];

        cTmp[0] = hexChars.charAt((b & 0xF0) >>> 4);
        cTmp[1] = hexChars.charAt(b & 0x0F);
        sbTmp.append(cTmp);

        return sbTmp.toString();
    }    
    public static byte[] fromHexString(final String encoded) {
        if ((encoded.length() % 2) != 0)
            throw new IllegalArgumentException("Input string must contain an even number of characters");

        final byte result[] = new byte[encoded.length()/2];
        final char enc[] = encoded.toCharArray();
        for (int i = 0; i < enc.length; i += 2) {
            StringBuilder curr = new StringBuilder(2);
            curr.append(enc[i]).append(enc[i + 1]);
            result[i/2] = (byte) Integer.parseInt(curr.toString(), 16);
        }
        return result;
    }
    
}
