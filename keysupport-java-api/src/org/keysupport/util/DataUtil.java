/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: DataUtil.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
 *
 * The KeySupport.org PIV API is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the KeySupport.org PIV API.  If not,
 * see <http://www.gnu.org/licenses/>.
 *
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 3 $
 * Last changed: $LastChangedDate: 2013-07-23 10:00:13 -0600 (Tue, 23 Jul 2013) $
 *****************************************************************************/

package org.keysupport.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.UUID;

/**
 * Provides utility methods to perform common operations.
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class DataUtil {

	private static final String numbers = "0123456789ABCDEF";

	// TODO: Security consideration, ensure input value is only a hex string as
	// defined
	// if ([^0-9a-f]) { throw exception }

	/**
	 * Convert a byte array to a Hex String
	 * 
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 * 
	 * @param ba
	 *            A byte array
	
	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte array */
	public static String byteArrayToString(byte[] ba) {
		if (ba == null) {
			return "";
		}
		StringBuffer hex = new StringBuffer(ba.length * 2);
		for (int i = 0; i < ba.length; i++) {
			hex.append(Integer.toString((ba[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return hex.toString().toUpperCase(Locale.US);
	}

	/**
	 * Method byteArrayToUUID.
	 * @param uuidBytes byte[]
	 * @return UUID
	 */
	public static UUID byteArrayToUUID(byte[] uuidBytes) {
		// uuidBytes is expected to be 16 bytes long
		byte[] ba_msb = new byte[8];
		System.arraycopy(uuidBytes, 0, ba_msb, 0, 8);
		byte[] ba_lsb = new byte[8];
		System.arraycopy(uuidBytes, 8, ba_lsb, 0, 8);
		BigInteger msb = new BigInteger(ba_msb);
		BigInteger lsb = new BigInteger(ba_lsb);
		return new UUID(msb.longValue(), lsb.longValue());
	}

	/**
	 * Convert a byte to a Hex String
	 * 
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 * 
	 * @param ba
	 *            A single byte
	
	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte */
	public static String byteToString(byte ba) {
		byte[] nba = { ba };
		return byteArrayToString(nba);
	}

	/**
	 * Method dateToString.
	 * @param date Date
	 * @return String
	 */
	public static String dateToString(Date date) {
		Calendar expireCa = new GregorianCalendar();
		// Use the incoming Date object to set the Year, Month, and Day
		expireCa.setTime(date);

		int year = expireCa.get(Calendar.YEAR);
		int month = expireCa.get(Calendar.MONTH);
		int day = expireCa.get(Calendar.DAY_OF_MONTH);

		StringBuffer sb = new StringBuffer();
		// I think we can trust we are working with 4 digit years
		sb.append(year);
		// Increment the month due to Jan = 0 with Calendar.MONTH
		month++;
		// Zeropad Month if needed
		if (month < 10) {
			sb.append('0');
		}
		sb.append(month);
		// Zeropad Day if needed
		if (day < 10) {
			sb.append('0');
		}
		sb.append(day);
		return sb.toString();
	}

	/**
	 * Convert a large byte array into multiple smaller byte arrays, with the
	 * output size determined by the caller
	 * 
	 * @param inputArray
	 *            An array of bytes
	 * @param arraySize
	 *            The size of each array object returned in the Enumeration
	 * @param zeroPad
	 *            Add a padding of zeros if the last array returned is shorter
	 *            than arraySize
	
	 * @return Enumeration An Enumeration of byte arrays of the size specified
	 *         by the caller */
	public static byte[][] getArrays(byte[] inputArray, int arraySize,
			boolean zeroPad) {
		byte[][] tdba = new byte[(int) Math.ceil(inputArray.length
				/ (double) arraySize)][arraySize];
		int start = 0;
		for (int i = 0; i < tdba.length; i++) {
			if (start + arraySize > inputArray.length) {
				byte[] lastArray;
				if (zeroPad) {
					lastArray = new byte[arraySize];
					Arrays.fill(lastArray, (byte) 0x00);
				} else {
					lastArray = new byte[inputArray.length - start];
				}
				System.arraycopy(inputArray, start, lastArray, 0,
						inputArray.length - start);
				tdba[i] = lastArray;
			} else {
				System.arraycopy(inputArray, start, tdba[i], 0, arraySize);
			}
			start += arraySize;
		}
		return tdba;
	}

	/**
	 * Method getByteArray.
	 * @param st String
	 * @return byte[]
	 */
	public static byte[] getByteArray(String st) {
		byte[] ba = null;
		try {
			ba = new String(st).getBytes("UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ba;
	}

	/**
	 * Convert a byte array of UTF-8 Characters to String
	 * 
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 * 
	 * @param ba
	 *            A single byte
	
	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte */
	public static String getString(byte[] ba) {
		String baSt = "";
		if (ba == null) {
			return baSt;
		}
		try {
			baSt = new String(ba, "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return baSt;
	}

	/**
	 * Method pad.
	 * @param inputArray byte[]
	 * @param padByte byte
	 * @param paddedArrayLen int
	 * @return byte[]
	 */
	public static byte[] pad(byte[] inputArray, byte padByte, int paddedArrayLen) {
		byte[] padArray = new byte[paddedArrayLen];
		Arrays.fill(padArray, padByte);
		System.arraycopy(inputArray, 0, padArray, 0, inputArray.length);
		return padArray;
	}

	/**
	 * Convert a Hex String to a byte array
	 * 
	 * The following method converts a String object to a byte[] object, where
	 * the only valid input characters is "0123456789ABCDEF".
	 * 
	 * @param s
	 *            Hexidecimal String object to convert to a byte array
	
	 * @return byte[] A byte array */
	public static byte[] stringToByteArray(String s) {
		if (s == null)
			return null;
		byte[] result = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i += 2) {
			int i1 = numbers.indexOf(s.charAt(i));
			int i2 = numbers.indexOf(s.charAt(i + 1));
			result[i / 2] = (byte) ((i1 << 4) | i2);
		}
		return result;
	}

	/**
	 * Method stringtoDate.
	 * @param date String
	 * @return Date
	 */
	public static Date stringtoDate(String date) {

		Calendar expireCa = new GregorianCalendar();

		int year = Integer.parseInt(date.substring(0, 4));
		int month = (Integer.parseInt(date.substring(4, 6)) - 1);
		int day = Integer.parseInt(date.substring(6, 8));
		expireCa.set(Calendar.YEAR, year);
		expireCa.set(Calendar.MONTH, month);
		expireCa.set(Calendar.DAY_OF_MONTH, day);

		// We set the remainder of the fields to Zero since the CHUID is only
		// "YYYYMMDD"
		expireCa.set(Calendar.HOUR, 0);
		expireCa.set(Calendar.HOUR_OF_DAY, 0);
		expireCa.set(Calendar.MINUTE, 0);
		expireCa.set(Calendar.SECOND, 0);
		expireCa.set(Calendar.MILLISECOND, 0);

		return expireCa.getTime();
	}

	/**
	 * Method uuidToByteArray.
	 * @param id UUID
	 * @return byte[]
	 */
	public static byte[] uuidToByteArray(UUID id) {
		ByteBuffer buffer = ByteBuffer.allocate(16);
		buffer.putLong(id.getMostSignificantBits());
		buffer.putLong(id.getLeastSignificantBits());
		return buffer.array();
	}

	/**
	 * XOR two byte arrays
	 * 
	 * The following method is used to XOR two byte array objects
	 * 
	 * @param array1
	 *            A byte array
	 * @param array2
	 *            A byte array
	
	 * @return byte[] The result of array1^array2 */
	public static byte[] XOR(byte[] array1, byte[] array2) {
		byte[] result = new byte[array1.length];
		for (int i = 0; i < array1.length; i++) {
			result[i] = (byte) (array1[i] ^ array2[i]);
		}
		return result;
	}

	/**************************************************************************
	 * PIN Prompting method
	 * 
	 * This is a utility method that makes use of Java Swing components to
	 * obtain a PIV PIN.
	 *************************************************************************/
	/*
	 * public static byte[] getPIVPIN(String dialog_label) { char[] pin =
	 * getPIN(dialog_label); byte[] pinbytes = new byte[pin.length]; for (int i
	 * = 0; i < pinbytes.length; i++) { pinbytes[i] = (byte)pin[i]; pin[i] =
	 * (char)0x00; } return pad(pinbytes, (byte)0xff, 8); }
	 */
	/**************************************************************************
	 * PIN/Password Prompting method
	 * 
	 * This is a utility method that makes use of Java Swing components to
	 * obtain general token activation data. (PIN or Password)
	 *************************************************************************/
	/*
	 * public static char[] getPIN(String dialog_label) { char[] pin = null;
	 * while (pin == null) { final JPasswordField jpf = new JPasswordField();
	 * JOptionPane jop = new JOptionPane(jpf, JOptionPane.PLAIN_MESSAGE,
	 * JOptionPane.OK_CANCEL_OPTION); JDialog dialog =
	 * jop.createDialog(dialog_label); dialog.setVisible(true); int result =
	 * (Integer)jop.getValue(); dialog.dispose(); if(result ==
	 * JOptionPane.OK_OPTION){ pin = jpf.getPassword(); } } return pin; }
	 */

}