/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCardHolderFacialImage.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

//import java.io.ByteArrayInputStream;
//import java.io.IOException;
import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;

/**
 */
public class PIVCardHolderFacialImage {

	// private final static boolean debug = true;

	private byte[] image;

	private byte[] fpo;

	public PIVCardHolderFacialImage() {
		encode();
	}

	/**
	 * Constructor for PIVCardHolderFacialImage.
	 * @param ba byte[]
	 */
	public PIVCardHolderFacialImage(byte[] ba) {
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
			byte[] value = child_tlv.getValue();
			switch (child_tag.getBytes()[0]) {
			case Tag.CFI_IMAGE: {
				this.image = value;
				System.out.println("GOT THE IMAGE");
				break;
			}
			default: {
				break;
			}
			}
		}
	}

	/*
	 * public BufferedImage getImage() { BufferedImage _image = null; try {
	 * _image = ImageIO.read(new ByteArrayInputStream(image)); }
	 * catch(IOException e) { e.printStackTrace(); } return _image; }
	 */

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
	 * Method getImage.
	 * @return byte[]
	 */
	public byte[] getImage() {
		return this.image;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		// sb.append("Card Holder Facial Image:Image:\t" + _image.toString());
		sb.append('\n');
		return sb.toString();
	}

}