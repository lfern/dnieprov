/*
   Copyright Isaac Levin

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package org.dnieprov.driver.utils.bertlv;

/**
 *
 * @author Isaac Levin
 */
public interface BerType {
	byte BOOLEAN = 0x01;
	byte INTEGER = 0x02;
	byte BIT_STRING = 0x03;
	byte OCTET_STRING = 0x04;
	byte NULL = 0x5;
	byte OID = 0x6;
	byte SEQUENCE = 0x30;
	byte IPADDRESS = 0x40;
	byte COUNTER32 = 0x41;
	byte GAUGE32 = 0x42;
	byte TIME_TICKS = 0x43;
	byte UINTEGER32 = 0x47;
        
        byte UTF8_STRING = 0x0c;
	
	byte GET_REQUEST_PDU = (byte)0xA0;
	byte GET_NEXT_REQUEST_PDU = (byte)0xA1;
	byte GET_RESPONSE_PDU = (byte)0xA2;
	byte SET_REQUEST_PDU = (byte)0xA3;
	byte TRAP_PDU = (byte)0xA4;
}
