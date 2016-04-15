/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: INTEGER.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;

/**
 * 
 * @author tejohnson
 * @version $Revision: 3 $
 */

/**
 * @author root
 * 
 */
public class INTEGER extends ASN1Object implements ASN1UniversalClass {

	private final Tag INTEGER = new Tag(Tag.INTEGER);

	/**
	 * 
	 */
	public INTEGER() {
		super();
		super.setValue(ASN1Factory.encodeASN1Object(this.INTEGER, null));
	}

	/**
	 * Constructor for INTEGER.
	 * @param encoded ASN1Object
	 */
	public INTEGER(ASN1Object encoded) {
		super(encoded);
	}

	/**
	 * Constructor for INTEGER.
	 * @param value BigInteger
	 */
	public INTEGER(BigInteger value) {
		super();
		super.setValue(ASN1Factory.encodeASN1Object(this.INTEGER,
				value.toByteArray()));
	}

	/**
	 * @param encoded
	
	 * @throws TLVEncodingException */
	public INTEGER(byte[] encoded) throws TLVEncodingException {
		super(encoded);
	}

	/**
	 * Constructor for INTEGER.
	 * @param value int
	 */
	public INTEGER(int value) {
		super();
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(value);
		BigInteger val = new BigInteger(1, bb.array());
		super.setValue(ASN1Factory.encodeASN1Object(this.INTEGER,
				val.toByteArray()));
	}

	/**
	 * Constructor for INTEGER.
	 * @param value byte
	 */
	public INTEGER(byte value) {
		super();
		super.setValue(ASN1Factory.encodeASN1Object(this.INTEGER, new byte[] { value }));
	}

	/**
	 * Method getIntegerValue.
	 * @return BigInteger
	 */
	public BigInteger getIntegerValue() {
		return new BigInteger(super.getValue());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.keysupport.asn1.ASN1UniversalClass#isA(org.keysupport.encoding.Tag)
	 */
	@Override
	public boolean isA(Tag tag) {
		return tag.equals(this.INTEGER);
	}

}
