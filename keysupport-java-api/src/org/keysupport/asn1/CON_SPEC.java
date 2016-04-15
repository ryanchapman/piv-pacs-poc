/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CON_SPEC.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
 * @author root
 * 
 * @version $Revision: 3 $
 */
public class CON_SPEC extends ASN1Object implements ASN1ConstructedType {

	private byte E_TAG_VALUE = Tag.CLASS_CONTEXT_SPECIFIC
			| Tag.TYPE_CONSTRUCTED;
	private byte I_TAG_VALUE = Tag.CLASS_CONTEXT_SPECIFIC
			| Tag.TYPE_PRIMITIVE;
	// Based on how we are created, we could be a Primitive or Constructed Type
	// For now we will only focus on Constructed Types based on our needs
	private byte TAG_VALUE = this.E_TAG_VALUE;
	public Tag CON_SPEC = new Tag(this.TAG_VALUE);

	/**
	 * Constructor for CON_SPEC.
	 * @param encoded ASN1Object
	 * @throws TLVEncodingException
	 */
	public CON_SPEC(ASN1Object encoded) throws TLVEncodingException {
		super(encoded);
		this.CON_SPEC = super.getTag();
	}

	/**
	 * Constructor for CON_SPEC.
	 * @param encoded byte[]
	 * @throws TLVEncodingException
	 */
	public CON_SPEC(byte[] encoded) throws TLVEncodingException {
		super(encoded);
		this.CON_SPEC = super.getTag();
	}

	/**
	 * Constructor for CON_SPEC.
	 * @param TagNum int
	 * @throws ASN1Exception
	 */
	public CON_SPEC(int TagNum) throws ASN1Exception {
		super();
		if (TagNum > 15 && TagNum < 0) {
			throw new ASN1Exception("Invalid Tag Number:" + TagNum);
		} else {
			byte topnib = (byte) (this.TAG_VALUE & (byte) 0xF0);
			byte botnib = (byte) ((byte) TagNum & (byte) 0x0F);
			byte VAL = (byte) (topnib | botnib);
			this.CON_SPEC = new Tag(VAL);
			super.setValue(ASN1Factory.encodeASN1Object(this.CON_SPEC, null));
		}
	}

	/**
	 * Constructor for CON_SPEC.
	 * @param TagNum int
	 * @param implicit boolean
	 * @throws ASN1Exception
	 */
	public CON_SPEC(int TagNum, boolean implicit, byte[] value) throws ASN1Exception {
		super();
		if (implicit) {
			this.TAG_VALUE = this.I_TAG_VALUE;
		}
		if (TagNum > 15 && TagNum < 0) {
			throw new ASN1Exception("Invalid Tag Number:" + TagNum);
		} else {
			byte topnib = (byte) (this.TAG_VALUE & (byte) 0xF0);
			byte botnib = (byte) ((byte) TagNum & (byte) 0x0F);
			byte VAL = (byte) (topnib | botnib);
			this.CON_SPEC = new Tag(VAL);
			super.setValue(ASN1Factory.encodeASN1Object(this.CON_SPEC, value));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.keysupport.asn1.ASN1ConstructedType#addComponent(org.keysupport.asn1
	 * .ASN1Object)
	 */
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
		try {
			baos.write(obj.getBytes());
		} catch (IOException e) {
			throw new ASN1Exception(e);
		}
		super.setValue(ASN1Factory.encodeASN1Object(this.CON_SPEC,
				baos.toByteArray()));
	}

	/*
	 * (non-Javadoc)
	 * 
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
	 */
	/**
	 * Method isA.
	 * @param tag Tag
	 * @return boolean
	 * @see org.keysupport.asn1.ASN1UniversalClass#isA(Tag)
	 */
	@Override
	public boolean isA(Tag tag) {
		return tag.equals(this.CON_SPEC);
	}

}
