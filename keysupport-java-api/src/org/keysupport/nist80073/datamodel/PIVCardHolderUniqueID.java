/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCardHolderUniqueID.java 18 2013-12-16 22:30:01Z grandamp@gmail.com $
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
 * @version $Revision: 18 $
 * Last changed: $LastChangedDate: 2013-12-16 15:30:01 -0700 (Mon, 16 Dec 2013) $
 *****************************************************************************/

package org.keysupport.nist80073.datamodel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVCardHolderUniqueID {

	private final static boolean debug = false;

	// Federal Agency Smart Credential Number
	private byte[] fascn = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// Agency Code
	private byte[] ac;// = { 0x00, 0x00, 0x00, 0x00 };

	// Organizational Identifier
	private byte[] oi;// = { 0x00, 0x00, 0x00, 0x00 };

	// DUNS
	private byte[] duns;// = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// GUID
	private byte[] guid = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// Expiration Date
	private byte[] expires = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// Asymmetric Signature
	private byte[] signature;

	// Error Detection Code
	private byte[] edc = { 0x00 }; // 1 digit

	private byte[] chuid;

	/**
	 * Constructor for PIVCardHolderUniqueID.
	 * @param ba byte[]
	 */
	public PIVCardHolderUniqueID(byte[] ba) {
		decode(ba);
		this.chuid = ba;
	}

	/**
	 * Constructor for PIVCardHolderUniqueID.
	 * @param FASCN FASCN (Required)
	 * @param agencyCode byte[] (May be null)
	 * @param organizationalIdentifier byte[] (May be null)
	 * @param DUNS byte[] (May be null)
	 * @param GUID byte[] (Required)
	 * @param expirationDate String (Required)
	 * @throws UnsupportedEncodingException
	 */
	public PIVCardHolderUniqueID(FASCN FASCN, byte[] agencyCode,
			byte[] organizationalIdentifier, byte[] DUNS, byte[] GUID,
			String expirationDate) throws UnsupportedEncodingException {

		setFASCN(FASCN.toByteArray());
		setAgencyCode(agencyCode);
		setOrganizationalIdentifier(organizationalIdentifier);
		setDUNS(DUNS);
		setGUID(GUID);
		setExpirationDate(expirationDate);

		encode();

	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	private void decode(byte[] ba) {

		Enumeration<?> children = BERTLVFactory.decodeTLV(ba);
		while (children.hasMoreElements()) {

			TLV child_tlv = (TLV) children.nextElement();
			Tag child_tag = child_tlv.getTag();
			byte[] value = child_tlv.getValue();

			switch (child_tag.getBytes()[0]) {
			case Tag.CHUID_FASCN: {
				this.fascn = value;
				break;
			}
			case Tag.CHUID_AGENCY_CODE: {
				this.ac = value;
				break;
			}
			case Tag.CHUID_ORG_ID: {
				this.oi = value;
				break;
			}
			case Tag.CHUID_DUNS: {
				this.duns = value;
				break;
			}
			case Tag.CHUID_GUID: {
				this.guid = value;
				break;
			}
			case Tag.CHUID_EXPIRATION_DATE: {
				this.expires = value;
				break;
			}
			case Tag.CHUID_SIGNATURE: {
				this.signature = value;
				break;
			}
			case Tag.CHUID_ERROR_DETECT_CODE: {
				this.edc = value;
				break;
			}
			default: {
				break;
			}
			}
		}

	}

	private void encode() {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			// FASC-N
			TLV _ftlv = BERTLVFactory
					.encodeTLV(new Tag(Tag.CHUID_FASCN), this.fascn);
			baos.write(_ftlv.getBytes());
			// Agency Code
			if (this.ac != null) {
				TLV _actlv = BERTLVFactory.encodeTLV(
					new Tag(Tag.CHUID_AGENCY_CODE), this.ac);
				baos.write(_actlv.getBytes());
			}
			// Organizational Identifier
			if (this.oi != null) {
				TLV _oitlv = BERTLVFactory.encodeTLV(
						new Tag(Tag.CHUID_ORG_ID), this.oi);
				baos.write(_oitlv.getBytes());
			}
			// DUNS
			if (this.duns != null) {
				TLV _dunstlv = BERTLVFactory.encodeTLV(
						new Tag(Tag.CHUID_DUNS), this.duns);
				baos.write(_dunstlv.getBytes());
			}
			// GUID
			TLV _guidtlv = BERTLVFactory.encodeTLV(new Tag(Tag.CHUID_GUID),
					this.guid);
			baos.write(_guidtlv.getBytes());
			// Expiration Date
			TLV _extlv = BERTLVFactory.encodeTLV(new Tag(
					Tag.CHUID_EXPIRATION_DATE), this.expires);
			baos.write(_extlv.getBytes());
			// Signature
			TLV _sigtlv = BERTLVFactory.encodeTLV(new Tag(Tag.CHUID_SIGNATURE),
					this.signature);
			baos.write(_sigtlv.getBytes());
			// Error Detect Code (Tag only, zero length)
			TLV _edctlv = BERTLVFactory.encodeTLV(new Tag(
					Tag.CHUID_ERROR_DETECT_CODE), null);
			baos.write(_edctlv.getBytes());
			this.chuid = baos.toByteArray();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method getAgencyCode.
	 * @return String
	 */
	public String getAgencyCode() {
		return DataUtil.getString(this.ac);
	}

	/**
	 * Method getDUNS.
	 * @return String
	 */
	public String getDUNS() {
		return DataUtil.getString(this.duns);
	}

	/**
	 * Method getBytes will return a CHUID object as it is currently
	 * represented in memory.  Use of any of the setXXX methods or
	 * getEncoded will alter the CHUID object in memory based on the
	 * encoding rules of this object, which may affect any previously
	 * applied signatures.
	 * 
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.chuid;
	}

	/**
	 * Method getEncoded will return a CHUID object encoded by this class
	 * which will alter any previously encoded CHUID object.  If the desire
	 * is to obtain the original CHUID bytes, consider using the getBytes()
	 * method.
	 * 
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		encode();
		return this.chuid;
	}

	/**
	 * Method getExpirationDate.
	 * @return Date
	 */
	public Date getExpirationDate() {
		return DataUtil.stringtoDate(DataUtil.getString(this.expires));
	}

	/**
	 * Method getExpirationString.
	 * @return String
	 */
	public String getExpirationString() {
		return DataUtil.getString(this.expires);
	}

	/**
	 * Method getFASCN.
	 * @return FASCN
	 * @throws IOException
	 */
	public FASCN getFASCN() throws IOException {
		return new FASCN(this.fascn);
	}

	/**
	 * Method getGUID.
	 * @return UUID
	 */
	public UUID getGUID() {
		return DataUtil.byteArrayToUUID(this.guid);
	}

	/**
	 * Method getOrganizationalIdentifier.
	 * @return String
	 */
	public String getOrganizationalIdentifier() {
		return DataUtil.getString(this.oi);
	}

	/**
	 * Method getSignatureBytes.
	 * @return byte[]
	 */
	public byte[] getSignatureBytes() {
		return this.signature;
	}

	/**
	 * Method getSignatureDataBytes.
	 * @return byte[]
	 */
	public byte[] getSignatureDataBytes() {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {

			if (debug) {
				System.out.println("Decodeing CHUID Signature Data");
			}

			Enumeration<?> children = BERTLVFactory.decodeTLV(this.chuid);
			while (children.hasMoreElements()) {

				TLV child_tlv = (TLV) children.nextElement();
				Tag child_tag = child_tlv.getTag();
				// byte[] value = child_tlv.getValue();

				switch (child_tag.getBytes()[0]) {

				case Tag.CHUID_FASCN: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_FASCN.");
					}
					break;
				}
				case Tag.CHUID_AGENCY_CODE: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_AGENCY_CODE.");
					}
					break;
				}
				case Tag.CHUID_ORG_ID: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_ORG_ID.");
					}
					break;
				}
				case Tag.CHUID_DUNS: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_DUNS.");
					}
					break;
				}
				case Tag.CHUID_GUID: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_GUID.");
					}
					break;
				}
				case Tag.CHUID_EXPIRATION_DATE: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_EXPIRATION_DATE.");
					}
					break;
				}
				case Tag.CHUID_ERROR_DETECT_CODE: {
					baos.write(child_tlv.getBytes());
					if (debug) {
						System.out.println("Decoded CHUID_ERROR_DETECT_CODE.");
					}
					break;
				}
				case Tag.CHUID_SIGNATURE: {
					// Do nothing with this data
					if (debug) {
						System.out
								.println("Excluding the asymmetric signature field");
					}
					break;
				}
				default: {
					// Everything else, even if not defined
					if (debug) {
						System.out.println("Including Unknown TLV: "
								+ DataUtil.byteArrayToString(child_tlv
										.getBytes()));
					}
					baos.write(child_tlv.getBytes());
					break;
				}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return baos.toByteArray();

	}

	/**
	 * Method setAgencyCode.
	 * @param agencyCode byte[]
	 */
	public void setAgencyCode(byte[] agencyCode) {
		this.ac = agencyCode;
		encode();
	}

	/**
	 * Method setDUNS.
	 * @param DUNS byte[]
	 */
	public void setDUNS(byte[] DUNS) {
		this.duns = DUNS;
		encode();
	}

	/**
	 * Method setExpirationDate.
	 * @param expriryDate Date
	 * @throws UnsupportedEncodingException
	 */
	public void setExpirationDate(Date expriryDate)
			throws UnsupportedEncodingException {
		this.expires = DataUtil.dateToString(expriryDate).getBytes("UTF-8");
		encode();
	}

	/**
	 * Method setExpirationDate.
	 * @param expriryDate String
	 * @throws UnsupportedEncodingException
	 */
	public void setExpirationDate(String expriryDate)
			throws UnsupportedEncodingException {
		this.expires = expriryDate.getBytes("UTF-8");
		encode();
	}

	/**
	 * Method setFASCN.
	 * @param FASCN byte[]
	 */
	public void setFASCN(byte[] FASCN) {
		this.fascn = FASCN;
		encode();
	}

	/**
	 * Method setFASCN.
	 * @param fascn FASCN
	 */
	public void setFASCN(FASCN fascn) {
		this.setFASCN(fascn.toByteArray());
	}

	/**
	 * Method setGUID.
	 * @param GUID byte[]
	 */
	public void setGUID(byte[] GUID) {
		this.guid = GUID;
		encode();
	}

	/**
	 * Method setGUID.
	 * @param GUID UUID
	 */
	public void setGUID(UUID GUID) {
		this.guid = DataUtil.uuidToByteArray(GUID);
		encode();
	}

	/**
	 * Method setOrganizationalIdentifier.
	 * @param organizationalIdentifier byte[]
	 */
	public void setOrganizationalIdentifier(byte[] organizationalIdentifier) {
		this.oi = organizationalIdentifier;
		encode();
	}

	/**
	 * Method setSignatureBytes.
	 * @param signatureBytes byte[]
	 */
	public void setSignatureBytes(byte[] signatureBytes) {
		this.signature = signatureBytes;
		encode();
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		FASCN myFascn = null;
		try {
			myFascn = this.getFASCN();
		} catch (IOException e) {
			e.printStackTrace();
		}
		StringBuffer sb = new StringBuffer();
		sb.append("Card Holder Unique ID:FASC-N:Agency Code:\t\t\t"
				+ myFascn.getAgencyCode());
		sb.append("\nCard Holder Unique ID:FASC-N:System Code:\t\t\t"
				+ myFascn.getSystemCode());
		sb.append("\nCard Holder Unique ID:FASC-N:Credential Number:\t\t\t"
				+ myFascn.getCredentialNumber());
		sb.append("\nCard Holder Unique ID:FASC-N:Credential Series:\t\t\t"
				+ myFascn.getCredentialSeries());
		sb.append("\nCard Holder Unique ID:FASC-N:Individual Credential Issue:\t"
				+ myFascn.getIndividualCredentialIssue());
		sb.append("\nCard Holder Unique ID:FASC-N:Person Identifier:\t\t\t"
				+ myFascn.getPersonIdentifier());
		sb.append("\nCard Holder Unique ID:FASC-N:Organizational Category:\t\t"
				+ myFascn.getOrganizationalCategory());
		sb.append("\nCard Holder Unique ID:FASC-N:Organizational Identifier:\t\t"
				+ myFascn.getOrganizationalIdentifier());
		sb.append("\nCard Holder Unique ID:FASC-N:Per/Org Association Category:\t"
				+ myFascn.getAssociationCategory());
		sb.append("\nCard Holder Unique ID:Agency Code:\t\t\t\t"
				+ this.getAgencyCode());
		sb.append("\nCard Holder Unique ID:Organization Identifier:\t\t\t"
				+ this.getOrganizationalIdentifier());
		sb.append("\nCard Holder Unique ID:DUNS:\t\t\t\t\t" + this.getDUNS());
		sb.append("\nCard Holder Unique ID:GUID:\t\t\t\t\t"
				+ this.getGUID().toString());
		sb.append("\nCard Holder Unique ID:Expiration Date:\t\t\t\t"
				+ this.getExpirationDate().toString());
		sb.append("\nCard Holder Unique ID:Signature Bytes:\t\t\t\t"
				+ DataUtil.byteArrayToString(this.signature));
		sb.append("\nCard Holder Unique ID:Error Detection Code:\t\t\t"
				+ DataUtil.byteArrayToString(this.edc));
		sb.append('\n');
		return sb.toString();
	}

}