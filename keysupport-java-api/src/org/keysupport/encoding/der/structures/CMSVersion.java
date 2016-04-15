/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CMSVersion.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.encoding.der.structures;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.INTEGER;
import org.keysupport.encoding.TLVEncodingException;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *       CMSVersion ::= INTEGER
 *                   { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
 * </pre>
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class CMSVersion {

	private INTEGER ever = new INTEGER();

	public final static int v0 = 0;
	public final static int v1 = 1;
	public final static int v2 = 2;
	public final static int v3 = 3;
	public final static int v4 = 4;
	public final static int v5 = 5;

	/**
	 * Constructor for CMSVersion.
	 * @param encoded ASN1Object
	 */
	public CMSVersion(ASN1Object encoded) {
		this.ever = new INTEGER(encoded);
	}

	/**
	 * Constructor for CMSVersion.
	 * @param encoded byte[]
	 * @throws TLVEncodingException
	 */
	public CMSVersion(byte[] encoded) throws TLVEncodingException {
		this.ever = new INTEGER(encoded);
	}

	/**
	 * Constructor for CMSVersion.
	 * @param ver int
	 * @throws ASN1Exception
	 */
	public CMSVersion(int ver) throws ASN1Exception {
		if (ver < v0 || ver > v5) {
			throw new ASN1Exception("Invalid version number: " + ver);
		} else {
			this.ever = new INTEGER((byte)ver);
		}
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.ever.getBytes();
	}
	
	/**
	 * Method getASN1Object.
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.ever;
	}

	/**
	 * Method getVersion.
	 * @return int
	 */
	public int getVersion() {
		return this.ever.getIntegerValue().intValue();
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		return "Version: " + this.getVersion();
	}

}
