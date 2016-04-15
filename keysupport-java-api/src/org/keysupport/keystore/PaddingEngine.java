/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PaddingEngine.java 16 2013-11-11 22:12:44Z grandamp@gmail.com $
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
 * @version $Revision: 16 $
 * Last changed: $LastChangedDate: 2013-11-11 15:12:44 -0700 (Mon, 11 Nov 2013) $
 *****************************************************************************/

package org.keysupport.keystore;

import java.util.Arrays;

/**
 * A utility class for various padding mechanisms.
 * 
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 16 $
 */
public class PaddingEngine {

	/**
	 * Method PKCS1v1_5Pad.
	 * 
	 * Padding mechanism defined in PKCS#1 v1.5, as well as:
	 *  <A HREF="http://www.ietf.org/rfc/rfc3447.txt">RFC3447</A>
	 * 
	 * @param message byte[]
	 * @param modsize int
	 * @return byte[]
	 */
	public static byte[] pkcs1v1_5Pad(byte[] message, int modsize) {

		byte[] newMessage = null;
		int messageOffset = 0;
		final byte[] pkcsPadBytes = new byte[] { (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0x00 };
		
		newMessage = new byte[modsize];
		Arrays.fill(newMessage, pkcsPadBytes[2]);
		System.arraycopy(pkcsPadBytes, 0, newMessage, 0, 2);
		messageOffset = newMessage.length - message.length;
		System.arraycopy(pkcsPadBytes, 3, newMessage, (messageOffset-1), 1);
		System.arraycopy(message, 0, newMessage, messageOffset, message.length);
		return newMessage;
	}
	
}
