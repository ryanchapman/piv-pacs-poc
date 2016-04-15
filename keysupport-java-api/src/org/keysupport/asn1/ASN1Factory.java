/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: ASN1Factory.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.asn1;

import java.util.Enumeration;
import java.util.Vector;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;

/**
 * @author root
 * 
 * @version $Revision: 3 $
 */
public class ASN1Factory extends BERTLVFactory {

	/**
	 * Method decodeASN1Object.
	 * @param value byte[]
	 * @return Enumeration<ASN1Object>
	 * @throws TLVEncodingException
	 */
	public static Enumeration<ASN1Object> decodeASN1Object(byte[] value)
			throws TLVEncodingException {
		Enumeration<TLV> en = decodeTLV(value);
		Vector<ASN1Object> objs = new Vector<ASN1Object>();
		while (en.hasMoreElements()) {
			objs.add(new ASN1Object(en.nextElement().getBytes()));
		}
		return objs.elements();
	}

	/**
	 * Method encodeASN1Object.
	 * @param tag Tag
	 * @param value byte[]
	 * @return ASN1Object
	 */
	public static ASN1Object encodeASN1Object(Tag tag, byte[] value) {
		TLV asn = encodeTLV(tag, value);
		return new ASN1Object(asn.getTag().getBytes(), asn.getEncodedLength(),
				asn.getValue(), asn.getBytes());
	}

	/**
	 * 
	 */
	public ASN1Factory() {
		// TODO Auto-generated constructor stub
	}
}
