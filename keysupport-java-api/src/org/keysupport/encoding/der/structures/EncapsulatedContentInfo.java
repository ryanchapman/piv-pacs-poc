/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: EncapsulatedContentInfo.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;
import org.keysupport.encoding.der.ObjectIdentifier;
import org.keysupport.util.DataUtil;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *     EncapsulatedContentInfo ::= SEQUENCE {
 *      eContentType ContentType,
 *      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 * 
 *     ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class EncapsulatedContentInfo {

	private SEQUENCE eci = new SEQUENCE();
	private ASN1Object ect = new ASN1Object();
	private ASN1Object ec = new ASN1Object();

	/**
	 * Constructor for EncapsulatedContentInfo.
	 * @param encoded ASN1Object
	 * @throws ASN1Exception
	 */
	public EncapsulatedContentInfo(ASN1Object encoded) throws ASN1Exception {
		this.eci = new SEQUENCE(encoded);
		this.decode();
	}

	/**
	 * Constructor for EncapsulatedContentInfo.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public EncapsulatedContentInfo(byte[] encoded) throws ASN1Exception {
		try {
			this.eci = new SEQUENCE(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.decode();
	}

	/**
	 * Constructor for EncapsulatedContentInfo.
	 * @param oid ObjectIdentifier
	 * @throws ASN1Exception
	 */
	public EncapsulatedContentInfo(ObjectIdentifier oid) throws ASN1Exception {
		this.ect = ASN1Factory.encodeASN1Object(new Tag(Tag.OBJECTID),
				oid.getEncoded());
		this.eci.addComponent(this.ect);
	}

	/**
	 * Method decode.
	 * @throws ASN1Exception
	 */
	private void decode() throws ASN1Exception {
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.eci.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.ect = en.nextElement();
			if (en.hasMoreElements()) {
				this.ec = en.nextElement();
			}
		}
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.eci.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.eci;
	}

	/**
	 * Method getContentType.
	 * @return ObjectIdentifier
	 */
	public ObjectIdentifier getContentType() {
		return new ObjectIdentifier(this.ect.getValue());
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("SEQUENCE {\n");
		sb.append("\t" + this.getContentType().toString());
		if (this.ec.getValue() != null) {
			sb.append(",c\t" + DataUtil.byteArrayToString(this.ec.getValue())
					+ "\n");
		} else {
			sb.append('\n');
		}
		sb.append("}\n");
		return sb.toString();
	}

}
