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


public class BerTlv {
	private BerTlvIdentifier tag;
	private int length;
	private byte[] value;
	
	
	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		this.length = length;
	}

	public BerTlvIdentifier getTag() {
		return tag;
	}

	public void setTag(BerTlvIdentifier tag) {
		this.tag = tag;
	}

	public byte[] getValue() {
		return value;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}

	public static BerTlv create(ByteArrayInputStream stream) {
		BerTlv tlv = new BerTlv();
		tlv.decode(stream);
		return tlv;
	}

	public void decode(byte[] data) {
		decode(new ByteArrayInputStream(data));
	}
	
	public void decode(ByteArrayInputStream stream) {
		// Decode Tag
		tag = new BerTlvIdentifier();
		tag.decode(stream);
		
		// Decode length
		int tmpLength = stream.read();
		if (tmpLength <= 127) { // 0111 1111
			// short length form
			length = tmpLength;
		} else if (tmpLength == 128) { // 1000 0000
			// length identifies indefinite form, will be set later
			length = tmpLength;
		} else {
			// long length form
			int numberOfLengthOctets = tmpLength & 127; // turn off 8th bit
			tmpLength = 0;
			for (int i = 0; i < numberOfLengthOctets; i++) {
				int nextLengthOctet = stream.read();
				tmpLength <<= 8;
				tmpLength |= nextLengthOctet;
			}
			length = tmpLength;
		}
		
		// decode value
		if (length == 128) { // 1000 0000
			// indefinite form
			stream.mark(0);
			int prevOctet = 1;
			int curOctet = 0;
			int len = 0;
			while (true) {
				len++;
				curOctet = stream.read();
				if (prevOctet == 0 && curOctet == 0) {
					break;
				}
				prevOctet = curOctet;
			}
			len -= 2;
			value = new byte[len];
			stream.reset();
			stream.read(value, 0, len);
			length = len;
		} else {
			// definite form
			value = new byte[length];
			stream.read(value, 0, length);
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
		// tag
		byte[] tagBytes = this.tag.getBytes();
		// encode length using definite form;
		// we don't use indefinite form since content is immediately available
		byte[] lengthBytes;
		if (value.length < 128) {
			// Short form
			lengthBytes = new byte[] { (byte) value.length };
		} else {
			// Long form
			byte[] tmpLengthBytes = BitManipulationHelper
					.intToByteArray(value.length);
			// Remove leading zero bytes
			int numOfLengthOctets = tmpLengthBytes.length;
			for (int i = 0; i < tmpLengthBytes.length; i++) {
				if (tmpLengthBytes[i] != 0) {
					break;
				}
				numOfLengthOctets--;
			}
			lengthBytes = new byte[numOfLengthOctets + 1];
			lengthBytes[0] = (byte) numOfLengthOctets;
			lengthBytes[0] |= 128; // Turn on 8th bit
			int curLengthBytesIdx = 1;
			for (int i = tmpLengthBytes.length - numOfLengthOctets; i < tmpLengthBytes.length; i++) {
				lengthBytes[curLengthBytesIdx++] = tmpLengthBytes[i];
			}
		}
		
		byte[] content = new byte[tagBytes.length + lengthBytes.length + value.length];
		System.arraycopy(tagBytes, 0, content, 0, tagBytes.length);
		System.arraycopy(lengthBytes, 0, content, tagBytes.length, lengthBytes.length);
		System.arraycopy(value, 0, content, tagBytes.length + lengthBytes.length, value.length);
		return content;
	}
	
	public String toString() {
		return "[TLV: ID=" + tag + ";Length=" + length + ";Value=" 
			+ ((value == null) ? "null" : value.length + " bytes") + "]";
	}
}
