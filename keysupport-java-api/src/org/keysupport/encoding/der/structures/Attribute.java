/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: Attribute.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
import org.keysupport.encoding.der.ObjectIdentifier;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *     Attribute ::= SEQUENCE {
 *      attrType OBJECT IDENTIFIER,
 *      attrValues SET OF AttributeValue }
 * </pre>
 * 
 * The AttributeValue is determined by the attrType OID.
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class Attribute {

	private SEQUENCE attr = new SEQUENCE();
	private ASN1Object id = new ASN1Object();
	private ASN1Object val = new ASN1Object();
	
	public Attribute() {
	}

	/**
	 * Constructor for Attribute.
	 * @param encoded ASN1Object
	 * @throws ASN1Exception
	 */
	public Attribute(ASN1Object encoded) throws ASN1Exception {
		this.attr = new SEQUENCE(encoded);
		this.decode();
	}

	/**
	 * Constructor for Attribute.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public Attribute(byte[] encoded) throws ASN1Exception {
		try {
			this.attr = new SEQUENCE(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.decode();
	}

	/**
	 * Method decode.
	 * @throws ASN1Exception
	 */
	private void decode() throws ASN1Exception {
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.attr.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.setAttrTypeOID(en.nextElement());
			this.setAttributeValues(en.nextElement());
		}
	}

	/**
	 * Method encode.
	 * @throws ASN1Exception
	 */
	private void encode() throws ASN1Exception {
		SEQUENCE tmpseq = new SEQUENCE();
		tmpseq.addComponent(this.id);
		tmpseq.addComponent(this.val);
		this.attr = tmpseq;
	}
	
	/**
	
	
	 * @return the val * @throws ASN1Exception */
	public Enumeration<ASN1Object> getAttributeValues() throws ASN1Exception {
		try {
			return ASN1Factory.decodeASN1Object(this.val.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
	}

	/**
	
	 * @return the id */
	public ObjectIdentifier getAttrTypeOID() {
		return new ObjectIdentifier(this.id.getValue());
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.attr.getBytes();
	}

	/**
	 * @param val
	 *            the val to set
	
	 * @throws ASN1Exception  */
	public void setAttributeValues(ASN1Object val) throws ASN1Exception {
		this.val = val;
		this.encode();
	}

	/**
	 * @param id
	 *            the id to set
	
	 * @throws ASN1Exception  */
	public void setAttrTypeOID(ASN1Object id) throws ASN1Exception {
		this.id = id;
		this.encode();
	}
}
