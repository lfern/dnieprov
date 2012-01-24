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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;


public class BerTlvIdentifier {
	public static final byte TAG_CLASS_UNIVERSAL = 0;
	public static final byte TAG_CLASS_APPLICATION = 1;
	public static final byte TAG_CLASS_CONTEXT_SPECIFIC = 2;
	public static final byte TAG_CLASS_PRIVATE = 3;

	private byte[] value;
        
        public BerTlvIdentifier (){
            
        }
        public BerTlvIdentifier (int value){
            init(value);
        }
	
	public boolean isPrimitiveEncoding() {
		if (value == null) {
			return false;
		}
		return !BitManipulationHelper.getBitValue(value[0], 6);
	}

	public byte getTagClass() {
		if (value == null) {
			return TAG_CLASS_UNIVERSAL;
		}
		if (!BitManipulationHelper.getBitValue(value[0], 8)
				&& !BitManipulationHelper.getBitValue(value[0], 7)) {
			return TAG_CLASS_UNIVERSAL;
		} else if (!BitManipulationHelper.getBitValue(value[0], 8)
				&& BitManipulationHelper.getBitValue(value[0], 7)) {
			return TAG_CLASS_APPLICATION;
		} else if (BitManipulationHelper.getBitValue(value[0], 8)
				&& !BitManipulationHelper.getBitValue(value[0], 7)) {
			return TAG_CLASS_CONTEXT_SPECIFIC;
		} else {
			return TAG_CLASS_PRIVATE;
		}
	}

	public int getTagValue() {
		if (value == null) {
			return 0;
		}
		if (value.length == 1) {
			return value[0];
		} else {
			byte[] tagBytes = Arrays.copyOfRange(value, 1, value.length);
			for (int i = 0; i < tagBytes.length - 1; i++) {
				// turn of 8th indicator bit
				tagBytes[i] = (byte) BitManipulationHelper.setBitValue(
						tagBytes[i], 8, false);
			}
			return new BigInteger(tagBytes).intValue();
		}
	}

        
	public void setTagValue(int tagValue) {
            init(tagValue);
        }
        
        private void init(int tagValue){
		if (tagValue >= -127 && tagValue <= 127) {
			value = new byte[] { (byte) tagValue };
		} else {
			value = BitManipulationHelper
					.removeLeadingZeroBytes(BitManipulationHelper
							.intToByteArray(tagValue));
		}
	}

	public void decode(ByteArrayInputStream stream) {
		int tlvIdFirstOctet = stream.read();

		value = new byte[] { (byte) tlvIdFirstOctet };
		// Check if id is multi-octet (bits 5 to 1 shall be encoded 11111)
		int mask = 31;
		if ((tlvIdFirstOctet & mask) == mask) {
			// Multi octet
			do {
				int tlvIdNextOctet = stream.read();
				boolean lastOctet = false;
				if (!BitManipulationHelper.getBitValue(tlvIdNextOctet, 8)) {
					lastOctet = true;
				}

				value = BitManipulationHelper.mergeArrays(value,
						new byte[] { (byte) tlvIdNextOctet });

				if (lastOctet) {
					break;
				}
			} while (true);
		}
	}
	
	public void encode(ByteArrayOutputStream stream) {
		try {
			stream.write(this.getBytes());
		} catch (IOException e) {
			throw new BerParsingException(e);
		}
	}
	
	public byte[] getBytes() {
		return value;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof BerTlvIdentifier)) {
			return false;
		}
		
		return Arrays.equals(value, ((BerTlvIdentifier)obj).value);
	}
	@Override
	public int hashCode() {
		return Arrays.hashCode(value);
	}
        @Override
	public String toString() {
		if (value == null) {
			return "NULL";
		}
		StringBuffer buf = new StringBuffer("[");
		for (int i = 0; i < value.length; i++) {
			buf.append("0x").append(Integer.toHexString(value[i])).append(" ");
		}
		buf.append("]");
		return buf.toString();
	}
}

