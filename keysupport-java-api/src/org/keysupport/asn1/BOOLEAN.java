/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: BOOLEAN.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.util.Arrays;

import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;

/**
 * @author root
 * 
 * @version $Revision: 3 $
 */
public class BOOLEAN extends ASN1Object implements ASN1UniversalClass {

	private final Tag BOOLEAN = new Tag(Tag.BOOLEAN);
	private final byte TRUE = (byte) 0xff;
	private final byte FALSE = (byte) 0x00;

	/**
	 * 
	 */
	public BOOLEAN() {
		super();
		super.setValue(ASN1Factory.encodeASN1Object(this.BOOLEAN, null));
	}

	/**
	 * Constructor for BOOLEAN.
	 * @param value boolean
	 */
	public BOOLEAN(boolean value) {
		super();
		if (value) {
			super.setValue(ASN1Factory.encodeASN1Object(this.BOOLEAN,
					new byte[] { this.TRUE }));
		} else {
			super.setValue(ASN1Factory.encodeASN1Object(this.BOOLEAN,
					new byte[] { this.FALSE }));
		}
	}

	/**
	 * @param encoded
	
	 * @throws TLVEncodingException */
	public BOOLEAN(byte[] encoded) throws TLVEncodingException {
		super(encoded);
	}

	/**
	 * Method getBooleanValue.
	 * @return boolean
	 */
	public boolean getBooleanValue() {
		return Arrays.equals(super.getValue(), new byte[] { this.TRUE });
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.keysupport.asn1.ASN1UniversalClass#isA(org.keysupport.encoding.Tag)
	 */
	@Override
	public boolean isA(Tag tag) {
		return tag.equals(this.BOOLEAN);
	}

}
