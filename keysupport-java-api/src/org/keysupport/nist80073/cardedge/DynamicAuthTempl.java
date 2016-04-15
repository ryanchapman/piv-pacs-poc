/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: DynamicAuthTempl.java 27 2014-07-08 17:03:33Z grandamp@gmail.com $
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
 * @version $Revision: 27 $
 * Last changed: $LastChangedDate: 2014-07-08 11:03:33 -0600 (Tue, 08 Jul 2014) $
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
public class DynamicAuthTempl {

	public static final int POP_TO_CARD_SYM_CHAL_REQ = 0;
	public static final int POP_TO_CARD_SYM = 1;
	public static final int POP_TO_CARD_RSA = 2;
	public static final int POP_TO_CARD_ECC = 3;
	public static final int POP_TO_TERM_SYM = 4;
	public static final int POP_TO_TERM_RSA = 5;
	public static final int POP_TO_TERM_ECC = 6;

	// private final static boolean debug = true;

	private byte templ_type;

	private byte[] witness;
	private byte[] challenge;
	private byte[] response;
	private byte[] exponent;

	private byte[] dat;

	/**
	 * Constructor for DynamicAuthTempl.
	 * 
	 * All Authentication attempts are initiated off-card, and occur based on
	 * the authentication scenerio.
	 * 
	 * This may include authentication to the card with the PIV Admin key to
	 * manage the PIV application data.
	 * 
	 * This may also include requesting authentication from the card too ensure
	 * there is a corresponding private key for a certificate on the card, such as
	 * PIV or CAK Authentication.
	 * 
	 * @param pop_type int
	 * @param data byte[]
	 */
	public DynamicAuthTempl(int pop_type, byte[] data) {

		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			TLV _ttav = null;

			switch (pop_type) {
			/*
			 * Supported.  Initially for authentication to the PIV application
			 * using the PIV ADMIN Key
			 */
			case POP_TO_CARD_SYM_CHAL_REQ: {
				this.challenge = data;
				_ttav = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT_CHALLENGE),
						this.challenge);
				baos.write(_ttav.getBytes());
				break;
			}
			case POP_TO_CARD_SYM: {
				this.response = data;
				_ttav = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT_RESPONSE),
						this.response);
				baos.write(_ttav.getBytes());
				break;
			}
			case POP_TO_CARD_RSA: {
				this.challenge = data;
				break;
			}
			case POP_TO_CARD_ECC: {
				this.response = data;
				break;
			}
			case POP_TO_TERM_SYM: {
				this.exponent = data;
				break;
			}
			/*
			 * Supported.  Initially for authentication to a terminal
			 * for the pivAuth or cardAuth keys
			 */
			case POP_TO_TERM_RSA: {
				this.challenge = data;
				_ttav = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT_RESPONSE),
						null);
				baos.write(_ttav.getBytes());
				_ttav = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT_CHALLENGE),
						this.challenge);
				baos.write(_ttav.getBytes());
				break;
			}
			case POP_TO_TERM_ECC: {
				this.challenge = data;
				_ttav = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT_RESPONSE),
						null);
				baos.write(_ttav.getBytes());
				_ttav = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT_CHALLENGE),
						this.challenge);
				baos.write(_ttav.getBytes());
				//this.exponent = data;
				break;
			}
			}
			/*
			 * Encode the overall template
			 */
			TLV _dat = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DAT),
					baos.toByteArray());
			/*
			 * Set our global with the encoded object
			 */
			this.dat = _dat.getBytes();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	/**
	 * Constructor for DynamicAuthTempl.
	 * @param ba byte[]
	 */
	public DynamicAuthTempl(byte[] ba) {
		decode(ba);
		this.dat = ba;
	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	public void decode(byte[] ba) {

		Enumeration<TLV> tlvs = BERTLVFactory.decodeTLV(ba);
		while (tlvs.hasMoreElements()) {
			TLV current_tlv = tlvs.nextElement();

			Enumeration<TLV> children = BERTLVFactory.decodeTLV(current_tlv
					.getValue());
			while (children.hasMoreElements()) {

				TLV child_tlv = children.nextElement();
				Tag child_tag = child_tlv.getTag();
				byte[] value = child_tlv.getValue();

				this.templ_type = child_tag.getBytes()[0];

				switch (this.templ_type) {

				case Tag.PIV_DAT_WITNESS: {
					this.witness = value;
					break;
				}
				case Tag.PIV_DAT_CHALLENGE: {
					this.challenge = value;
					break;
				}
				case Tag.PIV_DAT_RESPONSE: {
					this.response = value;
					break;
				}
				case Tag.PIV_DAT_EXPONENT: {
					this.exponent = value;
					break;
				}
				default: {
					break;
				}
				}
			}
		}

	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.dat;
	}

	/**
	 * Method getTemplateType.
	 * @return byte
	 */
	public byte getTemplateType() {
		return this.templ_type;
	}

	/**
	 * Method getTemplateValue.
	 * @return byte[]
	 */
	public byte[] getTemplateValue() {
		byte[] templ_value = null;
		switch (this.templ_type) {
		case Tag.PIV_DAT_WITNESS: {
			templ_value = this.witness;
			break;
		}
		case Tag.PIV_DAT_CHALLENGE: {
			templ_value = this.challenge;
			break;
		}
		case Tag.PIV_DAT_RESPONSE: {
			templ_value = this.response;
			break;
		}
		case Tag.PIV_DAT_EXPONENT: {
			templ_value = this.exponent;
			break;
		}
		}
		return templ_value;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Dynamic Authentication Template:");
		switch (this.templ_type) {
		case Tag.PIV_DAT_WITNESS: {
			sb.append("Witness:\t" + DataUtil.byteArrayToString(this.witness)
					+ "\n");
			break;
		}
		case Tag.PIV_DAT_CHALLENGE: {
			sb.append("Challenge:\t"
					+ DataUtil.byteArrayToString(this.challenge) + "\n");
			break;
		}
		case Tag.PIV_DAT_RESPONSE: {
			sb.append("Response:\t" + DataUtil.byteArrayToString(this.response)
					+ "\n");
			break;
		}
		case Tag.PIV_DAT_EXPONENT: {
			sb.append("Exponentiation:\t"
					+ DataUtil.byteArrayToString(this.exponent) + "\n");
			break;
		}
		}
		return sb.toString();
	}

}