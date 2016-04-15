/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVKeyHistoryObject.java 26 2014-07-08 17:03:16Z grandamp@gmail.com $
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
 * @version $Revision: 26 $
 * Last changed: $LastChangedDate: 2014-07-08 11:03:16 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.nist80073.datamodel;

import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

//TODO: PIVKeyHistoryObject

/**
 */
public class PIVKeyHistoryObject {

	private byte[] kho;
	
	private byte[] keysOnCardCerts;
	private byte[] keysOffCardCerts;
	private byte[] offCardURL;

	public PIVKeyHistoryObject() {
		encode();
	}

	/**
	 * Constructor for PIVKeyHistoryObject.
	 * @param ba byte[]
	 */
	public PIVKeyHistoryObject(byte[] ba) {
		decode(ba);
		this.kho = ba;
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
			case Tag.KHO_ON_CARD_CERTS: {
				this.setKeysOnCardCerts(value);
				break;
			}
			case Tag.KHO_OFF_CARD_CERTS: {
				this.setKeysOffCardCerts(value);
				break;
			}
			case Tag.KHO_OFF_CARD_URL: {
				this.setOffCardURL(value);
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
		return this.kho;
	}

	/**
	 * @return the keysOnCardCerts
	 */
	public byte[] getKeysOnCardCerts() {
		return keysOnCardCerts;
	}

	/**
	 * @param keysOnCardCerts the keysOnCardCerts to set
	 */
	public void setKeysOnCardCerts(byte[] keysOnCardCerts) {
		this.keysOnCardCerts = keysOnCardCerts;
	}

	/**
	 * @return the keysOffCardCerts
	 */
	public byte[] getKeysOffCardCerts() {
		return keysOffCardCerts;
	}

	/**
	 * @param keysOffCardCerts the keysOffCardCerts to set
	 */
	public void setKeysOffCardCerts(byte[] keysOffCardCerts) {
		this.keysOffCardCerts = keysOffCardCerts;
	}

	/**
	 * @return the offCardURL
	 */
	public String getOffCardURL() {
		return DataUtil.getString(this.offCardURL);
	}

	/**
	 * @param offCardURL the offCardURL to set
	 */
	public void setOffCardURL(byte[] offCardURL) {
		this.offCardURL = offCardURL;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Key History:On Card Certs:\t" + DataUtil.byteArrayToString(this.getKeysOnCardCerts()));
		sb.append("\nKey History:Off Card Certs:\t" + DataUtil.byteArrayToString(this.getKeysOffCardCerts()));
		sb.append("\nKey History:Off Card URL:\t" + this.getOffCardURL());
		sb.append('\n');
		return sb.toString();
	}

}