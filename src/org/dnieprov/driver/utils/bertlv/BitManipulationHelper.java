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
 * Utility class for bit and byte array manipulation.
 * @author Isaac Levin
 */
public final class BitManipulationHelper {
	
	private BitManipulationHelper() {
	}
	
	/**
	 * Returns bit value at specified position.
	 * @param value original number
	 * @param bitPosition 1st bit is 1, last bit is 32
	 * @return true the the bit is turned on
	 */
	public static boolean getBitValue(int value, int bitPosition) {
		if (bitPosition > 32) {
			throw new BerParsingException("Can't retrieve bit value at position " 
					+ bitPosition + ". Integer has only 32 bits.");
		}
		bitPosition--; // Convert to 0-based position
		int mask = 1 << bitPosition;
		
		return (value & mask) == 0 ? false : true;
	}
	
	/**
	 * Sets bit at specified position.
	 * @param value original number
	 * @param bitPosition bitPosition 1st bit is 1, last bit is 32
	 * @param bitValue true to turn the bit on
	 * @return new value
	 */
	public static int setBitValue(int value, int bitPosition, boolean bitValue) {
		if (bitPosition > 32) {
			throw new BerParsingException("Can't set bit value at position " 
					+ bitPosition + ". Integer has only 32 bits.");
		}
		bitPosition--; // Convert to 0-based position
		int mask = 1 << bitPosition;
		if (bitValue) {
			// Turn bit on
			return (value | mask);
		} else {
			// Turn bit off
			return (value & ~mask);
		}
	}
	
	/**
	 * Converts int to byte array.
	 * @param number original number
	 * @return result array of bytes
	 */
	public static byte[] intToByteArray(int number) {
		byte[] byteArray = new byte[4];
		byteArray[0] = (byte)((number >> 24) & 0xFF);
		byteArray[1] = (byte)((number >> 16) & 0xFF);
		byteArray[2] = (byte)((number >> 8) & 0xFF);
		byteArray[3] = (byte)(number & 0xFF);
		return byteArray;
	}
	
	/**
	 * Removes leading bytes with 0 value.
	 * @param buf original byte array
	 * @return Result byte array
	 */
	public static byte[] removeLeadingZeroBytes(byte[] buf) {
		int numOfUsedBytes = buf.length;
		for (int i = 0; i < buf.length; i++) {
			if (buf[i] != 0) {
				break;
			}
			numOfUsedBytes--;
		}
		
		if (numOfUsedBytes == 0) {
			// Leave last zero byte, otherwise the array will be empty
			numOfUsedBytes = 1;
		}

		byte[] resBuf = new byte[numOfUsedBytes];
		System.arraycopy(buf, buf.length - numOfUsedBytes, resBuf, 0, resBuf.length);
		return resBuf;
	}
	
	/**
	 * Merges two byte arrays.
	 * @param buf1 First byte array
	 * @param buf2 Second byte array
	 * @return Result byte array
	 */
	public static byte[] mergeArrays(byte[] buf1, byte[] buf2) {
		byte[] resBuf = new byte[buf1.length + buf2.length];
		System.arraycopy(buf1, 0, resBuf, 0, buf1.length);
		System.arraycopy(buf2, 0, resBuf, buf1.length, buf2.length);
		return resBuf;
	}
}
