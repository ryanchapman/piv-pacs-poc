/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: SEQUENCE.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;

/**
 */
public class SEQUENCE extends ASN1Object implements ASN1ConstructedType {

	public final Tag SEQUENCE = new Tag(Tag.SEQUENCE);

	public SEQUENCE() {
		super();
		super.setValue(ASN1Factory.encodeASN1Object(this.SEQUENCE, null));
	}

	/**
	 * Constructor for SEQUENCE.
	 * @param encoded ASN1Object
	 */
	public SEQUENCE(ASN1Object encoded) {
		super(encoded);
	}

	/**
	 * Constructor for SEQUENCE.
	 * @param encoded byte[]
	 * @throws TLVEncodingException
	 */
	public SEQUENCE(byte[] encoded) throws TLVEncodingException {
		super(encoded);
	}

	/**
	 * Method addComponent.
	 * @param obj ASN1Object
	 * @throws ASN1Exception
	 * @see org.keysupport.asn1.ASN1ConstructedType#addComponent(ASN1Object)
	 */
	@Override
	public void addComponent(ASN1Object obj) throws ASN1Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		if (super.getValue() != null) {
			try {
				baos.write(super.getValue());
			} catch (IOException e) {
				throw new ASN1Exception(e);
			}
		}
		if (obj.getBytes() != null) { 
			try {
				baos.write(obj.getBytes());
			} catch (IOException e) {
				throw new ASN1Exception(e);
			}
		}
		super.setValue(ASN1Factory.encodeASN1Object(new Tag(Tag.SEQUENCE),
				baos.toByteArray()));
	}

	/**
	 * Method addComponent.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 * @see org.keysupport.asn1.ASN1ConstructedType#addComponent(byte[])
	 */
	@Override
	public void addComponent(byte[] encoded) throws ASN1Exception {
		ASN1Object eobj = null;
		try {
			eobj = new ASN1Object(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.addComponent(eobj);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.keysupport.asn1.ASN1UniversalClass#isA(org.keysupport.encoding.Tag)
	 */
	@Override
	public boolean isA(Tag tag) {
		return tag.equals(this.SEQUENCE);
	}
}
