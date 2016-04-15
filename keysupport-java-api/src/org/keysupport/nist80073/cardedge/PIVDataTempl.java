/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVDataTempl.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.nist80073.cardedge;

import java.io.ByteArrayOutputStream;
import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVDataTempl {

	private final static boolean debug = false;

	private Tag tag;
	private byte[] data;

	private byte[] templ;

	/**
	 * Constructor for PIVDataTempl.
	 * @param ba byte[]
	 */
	public PIVDataTempl(byte[] ba) {
		if (debug) {
			System.out.println("PIVDataTempl<init>: "
					+ DataUtil.byteArrayToString(ba));
		}
		decode(ba);
		this.templ = ba;
	}

	/**
	 * Constructor for PIVDataTempl.
	 * @param tag Tag
	 * @param data byte[]
	 */
	public PIVDataTempl(Tag tag, byte[] data) {
		this.tag = tag;
		this.data = data;
		encode();
	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	public void decode(byte[] ba) {

		Enumeration<TLV> children = BERTLVFactory.decodeTLV(ba);
		while (children.hasMoreElements()) {

			TLV child_tlv = children.nextElement();
			Tag child_tag = child_tlv.getTag();
			byte[] value = child_tlv.getValue();

			switch (child_tag.getBytes()[0]) {

			case Tag.PIV_TAGLIST: {
				this.tag = child_tag;
				break;
			}
			case Tag.PIV_DATA: {
				this.data = value;
				break;
			}
			case Tag.PIV_DISCOVERY_OBJECT: {
				this.data = child_tag.getBytes();
				break;
			}
			default: {
				break;
			}
			}
		}

	}

	public void encode() {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			TLV _tag = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_TAGLIST),
					this.tag.getBytes());
			baos.write(_tag.getBytes());
			TLV _data = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DATA), this.data);
			baos.write(_data.getBytes());
			this.templ = baos.toByteArray();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method getData.
	 * @return byte[]
	 */
	public byte[] getData() {
		return this.data;
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		// Reminder: May need to address the overall object tag given use of the
		// single byte[] constructor (from decoding)
		return this.templ;
	}

	/**
	 * Method getTag.
	 * @return Tag
	 */
	public Tag getTag() {
		return this.tag;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("PIV Data:Tag:\t"
				+ DataUtil.byteArrayToString(this.tag.getBytes()));
		sb.append("\nPIV Data:Data:\t" + DataUtil.byteArrayToString(this.data));
		sb.append('\n');
		return sb.toString();
	}

}