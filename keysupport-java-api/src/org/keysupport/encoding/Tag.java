/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: Tag.java 30 2014-07-08 17:05:58Z grandamp@gmail.com $
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
 * @version $Revision: 30 $
 * Last changed: $LastChangedDate: 2014-07-08 11:05:58 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.encoding;

import java.util.Arrays;

import org.keysupport.util.DataUtil;

/**
 * <pre>
 * From: http://en.wikipedia.org/wiki/X.690
 * 
 * The identifier octets encode the ASN.1 tag (class and number) of the type of
 * the data value. Its structure is defined as follows:
 * 
 * Bit 8 and 7 of the identifier octet describe the class of the object. Note
 * that some of the ASN.1 types can be encoded using either primitive or a
 * constructed encoding at the option of the sender. The following values are
 * possible:
 * 
 * Class bit 8 bit 7 description Universal 0 0 The type is native to ASN.1
 * Application 0 1 The type is only valid for one specific application
 * Context-specific 1 0 Meaning of this type depends on the context (such as
 * within a sequence, set or choice) Private 1 1 Defined in private
 * specifications
 * 
 * Bit 6 (P/C) states whether the content is primitive like an INTEGER or
 * constructed, which means it again holds TLV values like a SET.
 * 
 * P/C bit 6 Primitive 0 Constructed 1
 * 
 * The remaining bits 5 to 1 contain the tag, which serves as the identifier of
 * the type of the content.
 * 
 * If the identifier is not universal it may have a tag with a number greater
 * than or equal to 31. In this case the tag does not fit in the 5 bits and has
 * to be encoded in the subsequent octets (111112 is not allowed as single tag
 * encoding).
 * 
 * Such a long-form identifier shall be encoded as follows:
 * 
 * -Bits 5 to 1 of the leading octet shall be encoded as 11111 -The subsequent
 * octets shall encode the number of the tag as follow --bit 8 of each octet
 * shall be set to one unless it is the last octet of the identifier octets
 * --bits 7 to 1 of the first subsequent octet, followed by bits 7 to 1 of each
 * subsequent octets including the last subsequent octet shall be the encoding
 * of an unsigned binary integer equal to the tag number, with bit 7 of the
 * first subsequent octet as the most significant bit --bits 7 to 1 of the first
 * subsequent octet shall not all be zero
 * </pre>
 * @author tejohnson
 * @version $Revision: 30 $
 */
public class Tag {

	private final static boolean debug = false;

	private byte[] tag;
	private byte tagType;
	private byte tagClass;
	private boolean constructed = false;

	public final static byte TYPE_CONSTRUCTED = (byte) 0x20;
	public final static byte TYPE_PRIMITIVE = (byte) 0x00;

	public final static byte CLASS_UNIVERSAL = (byte) 0x00;

	// Typical ASN.1 Tags
	public final static byte BMPSTRING = (byte) 0x1E;
	public final static byte BITSTRING = (byte) 0x03;
	public final static byte BOOLEAN = (byte) 0x01;
	public final static byte ENUMERATED = (byte) 0x0A;
	public final static byte GENERALSTRING = (byte) 0x1B;
	public final static byte GENERALIZEDTIME = (byte) 0x18;
	public final static byte IA5STRING = (byte) 0x16;
	public final static byte INTEGER = (byte) 0x02;
	public final static byte NULL = (byte) 0x05;
	public final static byte OBJECTID = (byte) 0x06;
	public final static byte OCTETSTRING = (byte) 0x04;
	public final static byte PRINTABLESTRING = (byte) 0x13;
	public final static byte T61STRING = (byte) 0x14;
	public final static byte UTF8STRING = (byte) 0x0C;
	public final static byte UNIVERSALSTRING = (byte) 0x1C;
	public final static byte UTCTIME = (byte) 0x17;
	public final static byte SEQUENCE = (byte) 0x30;
	public final static byte SEQUENCEOF = (byte) 0x30;
	public final static byte SET = (byte) 0x31;
	public final static byte SETOF = (byte) 0x31;

	public final static byte CLASS_APPLICATION = (byte) 0x40;
	public final static byte CLASS_CONTEXT_SPECIFIC = (byte) 0x80;
	public final static byte CLASS_PRIVATE = (byte) 0xC0;

	public final static byte PIV_GLOBAL_PIN = (byte) 0x00;
	public final static byte PIV_APPLICATION_PIN = (byte) 0x80;

	public final static byte[] PIV_APP_PROP_TMPL = new byte[] { (byte) 0x61 };
	public final static byte[] PIV_APP_AID = new byte[] { (byte) 0x4f };
	public final static byte[] PIV_APP_TAG_ALLOC = new byte[] { (byte) 0x79 };
	public final static byte[] PIV_APP_DESC = new byte[] { (byte) 0x50 };
	public final static byte[] PIV_APP_REF = new byte[] { (byte) 0x5f,
			(byte) 0x50 };

	public final static byte[] PIV_PIN_POLICY = new byte[] { (byte) 0x5f,
			(byte) 0x2f };

	public final static byte PIV_DAT = (byte) 0x7c;
	public final static byte PIV_DAT_WITNESS = (byte) 0x80;
	public final static byte PIV_DAT_CHALLENGE = (byte) 0x81;
	public final static byte PIV_DAT_RESPONSE = (byte) 0x82;
	public final static byte PIV_DAT_EXPONENT = (byte) 0x85;

	public final static byte PIV_TAGLIST = (byte) 0x5c;
	public final static byte PIV_DATA = (byte) 0x53;

	public final static byte AK_OBJECT = (byte) 0xac;
	public final static byte AK_ALGORITHM_ID = (byte) 0x80;
	public final static byte AK_PARAMETER = (byte) 0x81;

	public final static byte[] PKDO_OBJECT = { (byte) 0x7f, (byte) 0x49 };
	public final static byte PKDO_RSA_MODULUS = (byte) 0x81;
	public final static byte PKDO_RSA_PUB_EXP = (byte) 0x82;
	public final static byte PKDO_ECDSA_POINT = (byte) 0x86;

	public final static byte KHO_ON_CARD_CERTS = (byte) 0xC1;
	public final static byte KHO_OFF_CARD_CERTS = (byte) 0xC2;
	public final static byte KHO_OFF_CARD_URL = (byte) 0xF3;

	public final static byte PIV_CERT_CERTIFICATE = (byte) 0x70;
	public final static byte PIV_CERT_CERTINFO = (byte) 0x71;
	public final static byte PIV_CERT_MSCUID = (byte) 0x72;
	public final static byte ERROR_DETECT_CODE = (byte) 0xfe;
	// todo: eliminate all other error_detect_code's

	public final static byte CCC_CARD_IDENTIFIER = (byte) 0xf0;
	public final static byte CCC_VERSION = (byte) 0xf1;
	public final static byte CCC_GRAMMAR_VERSION = (byte) 0xf2;
	public final static byte CCC_APP_CARDURL = (byte) 0xf3;
	public final static byte CCC_PKCS15 = (byte) 0xf4;
	public final static byte CCC_REG_DATA_MODEL_NUMBER = (byte) 0xf5;
	public final static byte CCC_ACR_TABLE = (byte) 0xf6;
	public final static byte CCC_CARD_APDUS = (byte) 0xf7;
	public final static byte CCC_REDIRECTION_TAG = (byte) 0xfa;
	public final static byte CCC_CRS = (byte) 0xfb;
	public final static byte CCC_STS = (byte) 0xfc;
	public final static byte CCC_NEXT_CCC = (byte) 0xfd;
	public final static byte CCC_EA_CARDURL = (byte) 0xe3;
	public final static byte CCC_SECURITY_OBJECT_BUFFER = (byte) 0xb4;

	public final static byte SO_MAPPING = (byte) 0xba;
	public final static byte SO_SO = (byte) 0xbb;

	public final static byte CFI_IMAGE = (byte) 0xbc;

	public final static byte PI_NAME = (byte) 0x01;
	public final static byte PI_EMPLOYEE_AFFILIATION = (byte) 0x02;
	public final static byte PI_EXPIRATION_DATE = (byte) 0x04;
	public final static byte PI_AGENCY_CARD_SERIAL_NUMBER = (byte) 0x05;
	public final static byte PI_ISSUER_IDENTIFICATION = (byte) 0x06;
	public final static byte PI_ORGANIZATION_AFF_LN1 = (byte) 0x07;
	public final static byte PI_ORGANIZATION_AFF_LN2 = (byte) 0x08;

	// From Table 2 of 800-73-3 Part 1
	/**
	 * PIV Card Capabilities Container
	 */
	public static final byte[] PIV_CCC = new byte[] { (byte) 0x5f, (byte) 0xc1,
			(byte) 0x07 }; // '5FC107'

	/**
	 *
	 */
	public static final byte[] PIV_CHUID = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x02 }; // '5FC102'
	/**
	 *
	 */
	public static final byte[] PIV_CERT_PIVAUTH = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x05 }; // '5FC105'
	/**
	 *
	 */
	public static final byte[] PIV_CARDHOLDER_FINGERPRINTS = new byte[] {
			(byte) 0x5f, (byte) 0xc1, (byte) 0x03 }; // '5FC103'
	/**
	 *
	 */
	public static final byte[] PIV_SECURITY_OBJECT = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x06 }; // '5FC106'
	/**
	 *
	 */
	public static final byte[] PIV_CARDHOLDER_FACIAL_IMAGE = new byte[] {
			(byte) 0x5f, (byte) 0xc1, (byte) 0x08 }; // '5FC108'
	/**
	 *
	 */
	public static final byte[] PIV_PRINTED_INFORMATION = new byte[] {
			(byte) 0x5f, (byte) 0xc1, (byte) 0x09 }; // '5FC109'
	/**
	 *
	 */
	public static final byte[] PIV_CERT_DIGSIG = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x0a }; // '5FC10A'
	/**
	 *
	 */
	public static final byte[] PIV_CERT_KEYMGMT = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x0b }; // '5FC10B'
	/**
	 *
	 */
	public static final byte[] PIV_CERT_CARDAUTH = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x01 }; // '5FC101'
	/**
	 *
	 */
	public static final byte PIV_DISCOVERY_OBJECT = (byte) 0x7E; // '7E'
	/**
	 *
	 */
	public static final byte[] PIV_KEY_HISTORY_OBJECT = new byte[] {
			(byte) 0x5f, (byte) 0xc1, (byte) 0x0C }; // '5FC10C'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM01 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x0D }; // '5FC10D'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM02 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x0E }; // '5FC10E'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM03 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x0F }; // '5FC10F'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM04 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x10 }; // '5FC110'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM05 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x11 }; // '5FC111'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM06 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x12 }; // '5FC112'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM07 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x13 }; // '5FC113'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM08 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x14 }; // '5FC114'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM09 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x15 }; // '5FC115'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM10 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x16 }; // '5FC116'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM11 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x17 }; // '5FC117'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM12 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x18 }; // '5FC118'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM13 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x19 }; // '5FC119'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM14 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x1a }; // '5FC11A'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM15 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x1b }; // '5FC11B'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM16 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x1c }; // '5FC11C'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM17 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x1d }; // '5FC11D'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM18 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x1e }; // '5FC11E'
	/**
	 *
	 */
	public static final byte[] PIV_RET_CERT_KM19 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x1f }; // '5FC11F'
	/**
	 *
	 */
	public final static byte[] PIV_RET_CERT_KM20 = new byte[] { (byte) 0x5f,
			(byte) 0xc1, (byte) 0x20 }; // '5FC120'
	/**
	 *
	 */
	public static final byte[] PIV_CARDHOLDER_IRIS_IMAGES = new byte[] {
			(byte) 0x5f, (byte) 0xc1, (byte) 0x21 }; // '5FC121'

	/**
	 *
	 */
	public final static byte CHUID_FASCN = (byte) 0x30;
	/**
	 *
	 */
	public final static byte CHUID_AGENCY_CODE = (byte) 0x31;
	/**
	 *
	 */
	public final static byte CHUID_ORG_ID = (byte) 0x32;
	/**
	 *
	 */
	public final static byte CHUID_DUNS = (byte) 0x33;
	/**
	 *
	 */
	public final static byte CHUID_GUID = (byte) 0x34;
	/**
	 *
	 */
	public final static byte CHUID_EXPIRATION_DATE = (byte) 0x35;
	/**
	 *
	 */
	public final static byte CHUID_RFU_2 = (byte) 0x36;
	/**
	 *
	 */
	public final static byte CHUID_RFU_3 = (byte) 0x37;
	/**
	 *
	 */
	public final static byte CHUID_RFU_4 = (byte) 0x38;
	/**
	 *
	 */
	public final static byte CHUID_RFU_5 = (byte) 0x39;
	/**
	 *
	 */
	public final static byte CHUID_RFU_6 = (byte) 0x3A;
	/**
	 *
	 */
	public final static byte CHUID_RFU_7 = (byte) 0x3B;
	/**
	 *
	 */
	public final static byte CHUID_RFU_8 = (byte) 0x3C;
	/**
	 *
	 */
	public final static byte CHUID_AUTH_KEY_MAP = (byte) 0x3D;
	/**
	 *
	 */
	public final static byte CHUID_SIGNATURE = (byte) 0x3E;
	/**
	 *
	 */
	public final static byte CHUID_ERROR_DETECT_CODE = (byte) 0xFE;

	/**
	 * @param tag
	 */
	public Tag(byte tag) {
		this(new byte[] { tag });
	}

	/**
	 * @param tag
	 */
	public Tag(byte[] tag) {
		this.tag = tag;
		if ((tag[0] & (byte) 0x20) == TYPE_CONSTRUCTED) {
			if (debug) {
				System.out.println("Tag Type: CONSTRUCTED");
			}
			this.tagType = TYPE_CONSTRUCTED;
			this.constructed = true;
		} else {
			if (debug) {
				System.out.println("Tag Type: PRIMITIVE");
			}
			this.tagType = TYPE_PRIMITIVE;
			this.constructed = false;
		}
		switch (tag[0] & (byte) 0xC0) {
		case CLASS_UNIVERSAL:
			if (debug) {
				System.out.println("Tag Class: UNIVERSAL");
			}
			this.tagClass = CLASS_UNIVERSAL;
			break;
		case CLASS_APPLICATION:
			if (debug) {
				System.out.println("Tag Class: APPLICATION");
			}
			this.tagClass = CLASS_APPLICATION;
			break;
		case CLASS_CONTEXT_SPECIFIC:
			if (debug) {
				System.out.println("Tag Class: CONTEXT_SPECIFIC");
			}
			this.tagClass = CLASS_CONTEXT_SPECIFIC;
			break;
		case CLASS_PRIVATE:
			if (debug) {
				System.out.println("Tag Class: PRIVATE");
			}
			this.tagClass = CLASS_PRIVATE;
			break;
		}
		if (debug) {
			System.out.println(this.toString());
		}
	}

	/**
	
	 * @param obj Object
	 * @return boolean A boolean value. True if the othertag equals this tag to
	 *         the byte[] level. */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Tag)) {
			return false;
		}
		Tag other = (Tag) obj;
		return Arrays.equals(this.tag, other.getBytes());
	}

	/**
	 * Method hashCode.
	 * @return int
	 */
	@Override
	public int hashCode() {
		return Arrays.hashCode(this.tag);
	}

	/**
	
	 * @return byte[] A byte array containing the complete value of this Tag. */
	public byte[] getBytes() {
		return this.tag;
	}

	/**
	
	 * @return byte A byte value containing the Tag class. */
	public byte getTagClass() {
		return this.tagClass;
	}

	/**
	
	 * @return byte A byte value containing the Tag type. */
	public byte getTagType() {
		return this.tagType;
	}

	/**
	
	 * @return boolean A boolean value. True if constructed. */
	public boolean isConstructed() {
		return this.constructed;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		return "TAG:\n" + "TYPE:" + this.tagType + "\n" + "CLASS:"
				+ this.tagClass + "\n" + "FULL TAG:"
				+ DataUtil.byteArrayToString(this.tag);
	}

}