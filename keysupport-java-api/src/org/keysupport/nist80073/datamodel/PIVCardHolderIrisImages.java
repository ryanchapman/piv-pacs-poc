/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCardHolderIrisImages.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;

//TODO: PIVCardHolderIrisImages

/**
 */
public class PIVCardHolderIrisImages {

	// private final static boolean debug = true;

	private byte[] fpo;

	public PIVCardHolderIrisImages() {
		encode();
	}

	/**
	 * Constructor for PIVCardHolderIrisImages.
	 * @param ba byte[]
	 */
	public PIVCardHolderIrisImages(byte[] ba) {
		decode(ba);
		this.fpo = ba;
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
			// byte[] value = child_tlv.getValue();
			switch (child_tag.getBytes()[0]) {
			case Tag.CHUID_FASCN: {
				// this.fascn = value;
				break;
			}
			default: {
				break;
			}
			}
		}
	}

	public void encode() {
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.fpo;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("TEMPLATE:\t\t\t");
		sb.append('\n');
		return sb.toString();
	}

}