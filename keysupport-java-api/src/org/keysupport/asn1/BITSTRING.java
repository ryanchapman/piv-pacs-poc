/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: BITSTRING.java 29 2014-07-08 17:05:31Z grandamp@gmail.com $
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
 * @version $Revision: 29 $
 * Last changed: $LastChangedDate: 2014-07-08 11:05:31 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.asn1;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;

/**
 * 
 * @author tejohnson
 * @version $Revision: 29 $
 */
public class BITSTRING extends ASN1Object implements ASN1UniversalClass {

	/**
	 * Field BITSTRING.
	 */
	private final Tag BITSTRING = new Tag(Tag.BITSTRING);

	/**
	 * Field numUnused.
	 */
	private byte numUnused = (byte) 0x00;

	/**
	 * 
	 */
	public BITSTRING() {
		super();
		super.setValue(ASN1Factory.encodeASN1Object(this.BITSTRING, null));
	}

	/**
	 * Constructor for BITSTRING.
	 * 
	 * @param encoded
	 *            ASN1Object
	 */
	public BITSTRING(ASN1Object encoded) {
		super(encoded);
	}

	/**
	 * Constructor for BITSTRING.
	 * 
	 * @param value
	 *            BigInteger
	 * @param numUnused
	 *            int
	 * @throws ASN1Exception
	 */
	public BITSTRING(byte[] value, int numUnused) throws ASN1Exception {
		super();
		if (numUnused < 0 || numUnused > 7) {
			throw new ASN1Exception("Invaild number of unused bits: "
					+ numUnused);
		}
		this.numUnused = (byte) (numUnused & (byte) 0xff);
		ByteBuffer bb = ByteBuffer.allocate(value.length + 1);
		bb.put(this.numUnused);
		bb.put(value);
		super.setValue(ASN1Factory.encodeASN1Object(this.BITSTRING, bb.array()));
	}

	/**
	 * @param encoded
	 * 
	 * @throws TLVEncodingException
	 */
	public BITSTRING(byte[] encoded) throws TLVEncodingException {
		super(encoded);
	}

	/**
	 * Method getValue.
	 * 
	 * This will return the BITSTRING value without the number of unused bits header.
	 * 
	 * @return BigInteger
	 */
	@Override
	public byte[] getValue() {
		byte[] val = super.getValue();
		return Arrays.copyOfRange(val, 1, val.length);
	}

	/**
	 * Method getValue.
	 * 
	 * 
	 * @return int
	 */
	public int getNumUnusedBits() {
		byte[] val = super.getValue();
		return val[0];
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.keysupport.asn1.ASN1UniversalClass#isA(org.keysupport.encoding.Tag)
	 */
	/**
	 * Method isA.
	 * 
	 * @param tag
	 *            Tag
	 * 
	 * 
	 * @return boolean * @see org.keysupport.asn1.ASN1UniversalClass#isA(Tag)
	 */
	@Override
	public boolean isA(Tag tag) {
		return tag.equals(this.BITSTRING);
	}

}
