/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: NULL.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;

/**
 */
public class NULL extends ASN1Object {

	public static final Tag NULL = new Tag(Tag.NULL);

	/**
	 * Constructor for NULL.
	 * @throws TLVEncodingException
	 */
	public NULL() throws TLVEncodingException {
		super(new byte[] { (byte) 0x05, (byte) 0x00 });
	}

	// Submitted bytes are ignored
	/**
	 * Constructor for NULL.
	 * @param encoded byte[]
	 * @throws TLVEncodingException
	 */
	public NULL(byte[] encoded) throws TLVEncodingException {
		this();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.keysupport.asn1.ASN1UniversalClass#isA(org.keysupport.encoding.Tag)
	 */
	@Override
	public boolean isA(Tag tag) {
		return tag.equals(NULL);
	}
}
