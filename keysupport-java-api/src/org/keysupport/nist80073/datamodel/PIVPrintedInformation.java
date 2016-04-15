/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVPrintedInformation.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
public class PIVPrintedInformation {

	// private final static boolean debug = true;

	private byte[] name;
	private byte[] employee_aff;
	private byte[] expire_date;
	private byte[] agency_card_serial;
	private byte[] issuer_id;
	private byte[] org_aff_ln1;
	private byte[] org_aff_ln2;
	// private byte[] edc; //EDC is never used, consider removing.

	private byte[] pi;

	public PIVPrintedInformation() {
		encode();
	}

	/**
	 * Constructor for PIVPrintedInformation.
	 * @param ba byte[]
	 */
	public PIVPrintedInformation(byte[] ba) {
		decode(ba);
		this.pi = ba;
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

			case Tag.PI_NAME: {
				this.name = value;
				break;
			}
			case Tag.PI_EMPLOYEE_AFFILIATION: {
				this.employee_aff = value;
				break;
			}
			case Tag.PI_EXPIRATION_DATE: {
				this.expire_date = value;
				break;
			}
			case Tag.PI_AGENCY_CARD_SERIAL_NUMBER: {
				this.agency_card_serial = value;
				break;
			}
			case Tag.PI_ISSUER_IDENTIFICATION: {
				this.issuer_id = value;
				break;
			}
			case Tag.PI_ORGANIZATION_AFF_LN1: {
				this.org_aff_ln1 = value;
				break;
			}
			case Tag.PI_ORGANIZATION_AFF_LN2: {
				this.org_aff_ln2 = value;
				break;
			}
			/*
			 * case Tag.ERROR_DETECT_CODE: { this.edc = value; break; }
			 */default: {
				break;
			}
			}
		}
	}

	public void encode() {
	}

	/**
	 * Method getAgencyCardSerialNumber.
	 * @return String
	 */
	public String getAgencyCardSerialNumber() {
		return DataUtil.getString(this.agency_card_serial);
	}

	/**
	 * Method getEmployeeAffiliation.
	 * @return String
	 */
	public String getEmployeeAffiliation() {
		return DataUtil.getString(this.employee_aff);
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.pi;
	}

	/**
	 * Method getExpirationDate.
	 * @return String
	 */
	public String getExpirationDate() {
		return DataUtil.getString(this.expire_date);
	}

	/**
	 * Method getIssuerIdentification.
	 * @return String
	 */
	public String getIssuerIdentification() {
		return DataUtil.getString(this.issuer_id);
	}

	/**
	 * Method getName.
	 * @return String
	 */
	public String getName() {
		return DataUtil.getString(this.name);
	}

	/**
	 * Method getOrganizationAffLine1.
	 * @return String
	 */
	public String getOrganizationAffLine1() {
		return DataUtil.getString(this.org_aff_ln1);
	}

	/**
	 * Method getOrganizationAffLine2.
	 * @return String
	 */
	public String getOrganizationAffLine2() {
		return DataUtil.getString(this.org_aff_ln2);
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();

		sb.append("Printed Information:Name:\t\t\t\t" + this.getName());
		sb.append("\nPrinted Information:Employee Affiliation:\t\t"
				+ this.getEmployeeAffiliation());
		sb.append("\nPrinted Information:Expiration date:\t\t\t"
				+ this.getExpirationDate());
		sb.append("\nPrinted Information:Agency Card Serial Number:\t\t"
				+ this.getAgencyCardSerialNumber());
		sb.append("\nPrinted Information:Issuer Identification:\t\t"
				+ this.getIssuerIdentification());
		if (this.org_aff_ln1 != null) {
			sb.append("\nPrinted Information:Organization Affiliation (Line 1):\t"
					+ this.getOrganizationAffLine1());
		}
		if (this.org_aff_ln2 != null) {
			sb.append("\nPrinted Information:Organization Affiliation (Line 2):\t"
					+ this.getOrganizationAffLine2());
		}
		sb.append('\n');
		return sb.toString();
	}

}