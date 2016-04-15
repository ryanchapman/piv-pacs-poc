/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: TLV.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.encoding;

import java.util.Enumeration;

import org.keysupport.util.DataUtil;

/**
 */
public class TLV {

	private Tag tag;
	private byte[] encoded_length;
	private int length;
	private byte[] value;

	private byte[] TLV;

	/*
	 * Creates a TLV object using BERLTVFactory assuming the Byte array contains
	 * only one TLV. Otherwise, only the first TLV object will be used for this
	 * TLV (Peers will be discarded). This constructor is intended to be used to
	 * initialize ASN.1 Primitives:
	 * 
	 * PRIMITIVES -- these are "universal" ASN.1 simple types.
	 * 
	 * INTEGER, ENUMERATED, BIT STRING, OCTET STRING, NULL OBJECT IDENTIFIER,
	 * SEQUENCE (OF), SET (OF) UTF8String, PrintableString, T61String,
	 * IA5String, UTCTime, GeneralizedTime, BMPString, UniversalString.
	 */
	/**
	 * Constructor for TLV.
	 * @param encoded byte[]
	 * @throws TLVEncodingException
	 */
	public TLV(byte[] encoded) throws TLVEncodingException {
		Enumeration<TLV> tlvs = BERTLVFactory.decodeTLV(encoded);
		if (tlvs != null && tlvs.hasMoreElements()) {
			// Initialize this TLV object
			TLV tmp = tlvs.nextElement();
			this.tag = tmp.getTag();
			this.encoded_length = tmp.getEncodedLength();
			this.value = tmp.getValue();
			this.TLV = tmp.getBytes();
		} else {
			throw new TLVEncodingException(
					"Byte Array does not contain a TLV object");
		}
	}

	// Only a BERLTVFactory should create a TLV object.
	/**
	 * Constructor for TLV.
	 * @param tag_bytes byte[]
	 * @param encoded_length byte[]
	 * @param value byte[]
	 * @param TLV byte[]
	 */
	public TLV(byte[] tag_bytes, byte[] encoded_length, byte[] value, byte[] TLV) {
		this.tag = new Tag(tag_bytes);
		this.encoded_length = encoded_length;
		this.value = value;
		this.TLV = TLV;

		if (value == null) {
			this.length = 0;
		} else {
			this.length = this.value.length;
		}
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.TLV;
	}

	/**
	 * Method getChildren.
	 * @return Enumeration<TLV>
	 */
	public Enumeration<TLV> getChildren() {
		return BERTLVFactory.decodeTLV(this.value);
	}

	/**
	 * Method getEncodedLength.
	 * @return byte[]
	 */
	public byte[] getEncodedLength() {
		return this.encoded_length;
	}

	/**
	 * Method getLength.
	 * @return int
	 */
	public int getLength() {
		return this.value.length;
	}

	/**
	 * Method getTag.
	 * @return Tag
	 */
	public Tag getTag() {
		return this.tag;
	}

	/**
	 * Method getValue.
	 * @return byte[]
	 */
	public byte[] getValue() {
		return this.value;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		return "BER-TLV:\n" + "TAG Data:" + this.tag.toString() + "\n" + "LEN:"
				+ this.length + "\n" + "VAL:"
				+ DataUtil.byteArrayToString(this.value);

	}

}