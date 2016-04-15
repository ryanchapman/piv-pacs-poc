/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCardApplicationProperty.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.nist80073.datamodel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVCardApplicationProperty {

	// private final static boolean debug = true;

	private byte[] aid;
	private byte[] tag_alloc;
	private byte[] description;
	private byte[] reference;

	private byte[] pcap;

	/**
	 * Constructor for PIVCardApplicationProperty.
	 * @param ba byte[]
	 */
	public PIVCardApplicationProperty(byte[] ba) {
		decode(ba);
		this.pcap = ba;
	}

	/**
	 * Constructor for PIVCardApplicationProperty.
	 * @param aid byte[]
	 * @param tag_alloc byte[]
	 * @param description byte[]
	 * @param ref byte[]
	 */
	public PIVCardApplicationProperty(byte[] aid, byte[] tag_alloc,
			byte[] description, byte[] ref) {
		this.aid = aid;
		this.tag_alloc = tag_alloc;
		this.description = description;
		this.reference = ref;
		encode();

	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	public void decode(byte[] ba) {

		Enumeration<?> children = BERTLVFactory.decodeTLV(ba);
		while (children.hasMoreElements()) {

			TLV child_tlv = (TLV) children.nextElement();
			Tag child_tag = child_tlv.getTag();
			byte[] value = child_tlv.getValue();

			switch (child_tag.getBytes()[0]) {
			case (byte)0x4f: {
				this.aid = value;
				break;
			}
			case (byte)0x79: {
				this.tag_alloc = value;
				break;
			}
			case (byte)0x50: {
				this.description = value;
				break;
			}
			case (byte)0x5f: {
				this.reference = value;
				break;
			}
			default: {
				break;
			}
			}
		}
	}

	private void encode() {
		// BER-TLV Encode all of the attributes, then set the primary byte array
		// representing the object
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {

			// AID
			TLV _aidtlv = BERTLVFactory
					.encodeTLV(new Tag(Tag.PIV_APP_AID), this.aid);
			baos.write(_aidtlv.getBytes());

			// TAG ALLOC
			TLV _tagalloctlv = BERTLVFactory.encodeTLV(new Tag(
					Tag.PIV_APP_TAG_ALLOC), this.tag_alloc);
			baos.write(_tagalloctlv.getBytes());

			// DESCRIPTION
			TLV _destlv = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_APP_DESC),
					this.description);
			baos.write(_destlv.getBytes());

			// REFERENCE
			TLV _reftlv = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_APP_REF),
					this.reference);
			baos.write(_reftlv.getBytes());

		} catch (IOException e) {
			e.printStackTrace();
		}
		this.pcap = baos.toByteArray();
	}

	/**
	 * Method getAID.
	 * @return byte[]
	 */
	public byte[] getAID() {
		return this.aid;
	}

	/**
	 * Method getDescription.
	 * @return String
	 */
	public String getDescription() {
		return DataUtil.getString(this.description);
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.pcap;
	}

	/**
	 * Method getReference.
	 * @return String
	 */
	public String getReference() {
		return DataUtil.getString(this.reference);
	}

	/**
	 * Method getTagAlloc.
	 * @return byte[]
	 */
	public byte[] getTagAlloc() {
		return this.tag_alloc;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("PIV App Property:AID:\t\t"
				+ DataUtil.byteArrayToString(this.getAID()));
		sb.append("\nPIV App Property:Tag Alloc:\t"
				+ DataUtil.byteArrayToString(this.getTagAlloc()));
		if (this.description != null) {
			sb.append("\nPIV App Property:Description:\t"
					+ this.getDescription());
		}
		if (this.reference != null) {
			sb.append("\nPIV App Property:Reference:\t" + this.getReference());
		}
		sb.append('\n');
		return sb.toString();
	}

}