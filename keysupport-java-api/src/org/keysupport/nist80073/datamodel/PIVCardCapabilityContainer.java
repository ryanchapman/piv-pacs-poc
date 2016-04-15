/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCardCapabilityContainer.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
import org.keysupport.util.DataUtil;

/**
 */
public class PIVCardCapabilityContainer {

	// private final static boolean debug = true;

	private byte[] card_identifier;
	private byte[] version;
	private byte[] grammar_version;
	private byte[] app_cardurl;
	private byte[] pkcs15;
	private byte[] reg_data_model_number;
	private byte[] acr_table;
	private byte[] card_apdus;
	private byte[] redirection_tag;
	private byte[] cts;
	private byte[] sts;
	private byte[] next_ccc;
	private byte[] ea_cardurl;
	private byte[] security_object_buffer;
	private byte[] edc;

	private byte[] ccc;

	public PIVCardCapabilityContainer() {
		encode();
	}

	/**
	 * Constructor for PIVCardCapabilityContainer.
	 * @param ba byte[]
	 */
	public PIVCardCapabilityContainer(byte[] ba) {
		decode(ba);
		this.ccc = ba;
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
			case Tag.CCC_CARD_IDENTIFIER: {
				this.card_identifier = value;
				break;
			}
			case Tag.CCC_VERSION: {
				this.version = value;
				break;
			}
			case Tag.CCC_GRAMMAR_VERSION: {
				this.grammar_version = value;
				break;
			}
			case Tag.CCC_APP_CARDURL: {
				this.app_cardurl = value;
				break;
			}
			case Tag.CCC_PKCS15: {
				this.pkcs15 = value;
				break;
			}
			case Tag.CCC_REG_DATA_MODEL_NUMBER: {
				this.reg_data_model_number = value;
				break;
			}
			case Tag.CCC_ACR_TABLE: {
				this.acr_table = value;
				break;
			}
			case Tag.CCC_CARD_APDUS: {
				this.card_apdus = value;
				break;
			}
			case Tag.CCC_REDIRECTION_TAG: {
				this.redirection_tag = value;
				break;
			}
			case Tag.CCC_CRS: {
				this.cts = value;
				break;
			}
			case Tag.CCC_STS: {
				this.sts = value;
				break;
			}
			case Tag.CCC_NEXT_CCC: {
				this.next_ccc = value;
				break;
			}
			case Tag.CCC_EA_CARDURL: {
				this.ea_cardurl = value;
				break;
			}
			case Tag.CCC_SECURITY_OBJECT_BUFFER: {
				this.security_object_buffer = value;
				break;
			}
			case Tag.ERROR_DETECT_CODE: {
				this.edc = value;
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
		return this.ccc;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("CCC:Card Identifier:\t\t\t\t"
				+ DataUtil.byteArrayToString(this.card_identifier));
		sb.append("\nCCC:Capability Container version number:\t"
				+ DataUtil.byteArrayToString(this.version));
		sb.append("\nCCC:Capability Grammar version number:\t\t"
				+ DataUtil.byteArrayToString(this.grammar_version));
		sb.append("\nCCC:Applications CardURL:\t\t\t"
				+ DataUtil.byteArrayToString(this.app_cardurl));
		sb.append("\nCCC:PKCS#15:\t\t\t\t\t"
				+ DataUtil.byteArrayToString(this.pkcs15));
		sb.append("\nCCC:Registered Data Model number:\t\t"
				+ DataUtil.byteArrayToString(this.reg_data_model_number));
		sb.append("\nCCC:Access Control Rule Table:\t\t\t"
				+ DataUtil.byteArrayToString(this.acr_table));
		sb.append("\nCCC:Card APDUs:\t\t\t\t\t"
				+ DataUtil.byteArrayToString(this.card_apdus));
		sb.append("\nCCC:Redirection Tag:\t\t\t\t"
				+ DataUtil.byteArrayToString(this.redirection_tag));
		sb.append("\nCCC:Capability Tuples (CTs):\t\t\t"
				+ DataUtil.byteArrayToString(this.cts));
		sb.append("\nCCC:Status Tuples (STs):\t\t\t"
				+ DataUtil.byteArrayToString(this.sts));
		sb.append("\nCCC:Next CCC:\t\t\t\t\t"
				+ DataUtil.byteArrayToString(this.next_ccc));
		if (this.ea_cardurl != null) {
			sb.append("\nCCC:Extended Application CardURL (optional):\t"
					+ DataUtil.byteArrayToString(this.ea_cardurl));
		}
		if (this.security_object_buffer != null) {
			sb.append("\nCCC:Security Object Buffer (optional):\t\t"
					+ DataUtil.byteArrayToString(this.security_object_buffer));
		}
		sb.append("\nCCC:Error Detection Code:\t\t\t"
				+ DataUtil.byteArrayToString(this.edc));
		sb.append('\n');
		return sb.toString();
	}

}