/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: DigestEngine.java 18 2013-12-16 22:30:01Z grandamp@gmail.com $
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
 * @version $Revision: 18 $
 * Last changed: $LastChangedDate: 2013-12-16 15:30:01 -0700 (Mon, 16 Dec 2013) $
 *****************************************************************************/

package org.keysupport.keystore;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 18 $
 */
public class DigestEngine {

	/**
	 * Method mD5Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * @return byte[]
	 */
	public static byte[] mD5Sum(byte[] ba) {
		return xSum(ba, "MD5", null);
	}

	/**
	 * Method mD5Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] mD5Sum(byte[] ba, String provider) {
		return xSum(ba, "MD5", provider);
	}

	/**
	 * Method sHA1Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA1Sum(byte[] ba) {
		return xSum(ba, "SHA-1", null);
	}

	/**
	 * Method sHA1Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA1Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-1", provider);
	}

	/**
	 * Method sHA256Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA256Sum(byte[] ba) {
		return xSum(ba, "SHA-256", null);
	}

	/**
	 * Method sHA256Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA256Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-256", provider);
	}

	/**
	 * Method sHA384Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA384Sum(byte[] ba) {
		return xSum(ba, "SHA-384", null);
	}

	/**
	 * Method sHA384Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA384Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-384", provider);
	}

	/**
	 * Method sHA512Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA512Sum(byte[] ba) {
		return xSum(ba, "SHA-512", null);
	}

	/**
	 * Method sHA512Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA512Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-512", provider);
	}

	/**
	 * Method xSum.
	 * 
	 * @param ba
	 *            byte[]
	 * @param digestAlg
	 *            String
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	private static byte[] xSum(byte[] ba, String digestAlg, String provider) {
		byte[] digest = null;
		MessageDigest md = null;
		try {
			if (null == provider) {
				md = MessageDigest.getInstance(digestAlg);
			} else {
				md = MessageDigest.getInstance(digestAlg, provider);
			}
			md.update(ba);
			digest = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return digest;
	}

	// TODO: Add methods for IO Streams as well

}
