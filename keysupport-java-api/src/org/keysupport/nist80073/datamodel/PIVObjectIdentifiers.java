/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVObjectIdentifiers.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import org.keysupport.encoding.der.ObjectIdentifier;

/**
 */
public interface PIVObjectIdentifiers {

	/******************************************************************************
	 * 
	 * NIST joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
	 * csor(3)
	 * 
	 *****************************************************************************/

	static final String CSOR = "2.16.840.1.101.3";

	/******************************************************************************
	 * 
	 * NIST joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
	 * csor(3) PIV(6)
	 * 
	 *****************************************************************************/
	static final String PIV = CSOR + ".6";

	// PIV eContent Types

	/******************************************************************************
	 * 
	 * The associated content is the concatenated contents of the CHUID,
	 * excluding the authentication key map and the asymmetric signature field.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier id_PIV_CHUIDSecurityObject = new ObjectIdentifier(
			PIV + ".1");

	/******************************************************************************
	 * 
	 * The associated content is the concatenated CBEFF_HEADER +
	 * STD_BIOMETRIC_RECORD.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier id_PIV_biometricObject = new ObjectIdentifier(
			PIV + ".2");

	// PIV Attributes

	/******************************************************************************
	 * 
	 * The attribute value is of type DirectoryString and specifies the PIV
	 * cardholder�s name.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier pivCardholder_Name = new ObjectIdentifier(PIV
			+ ".3");

	/******************************************************************************
	 * 
	 * The attribute value is an X.501 type Name and specifies the DN associated
	 * with the PIV cardholder in the PIV certificate(s).
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier pivCardholder_DN = new ObjectIdentifier(PIV
			+ ".4");

	/******************************************************************************
	 * 
	 * The attribute value is an X.501 type Name and specifies the subject name
	 * that appears in the PKI certificate for the entity that signed the
	 * biometric or CHUID.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier pivSigner_DN = new ObjectIdentifier(PIV
			+ ".5");

	/******************************************************************************
	 * 
	 * The pivFASC-N OID may appear as a name type in the otherName field of the
	 * subjectAltName extension of X.509 certificates or a signed attribute in
	 * CMS external signatures. Where used as a name type, the syntax is OCTET
	 * STRING. Where used as an attribute, the attribute value is of type OCTET
	 * STRING. In each case, the value specifies the FASC-N of the PIV card.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier pivFASC_N = new ObjectIdentifier(PIV + ".6");

	// PIV Extended Key Usage

	/******************************************************************************
	 * 
	 * This specifies that the public key may be used to verify signatures on
	 * PIV CHUIDs and PIV biometrics.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier id_PIV_content_signing = new ObjectIdentifier(
			PIV + ".7");

	/******************************************************************************
	 * 
	 * This specifies that the public key is used to authenticate the PIV card
	 * rather than the PIV cardholder.
	 * 
	 *****************************************************************************/
	static final ObjectIdentifier id_PIV_cardAuth = new ObjectIdentifier(PIV
			+ ".8");

	// From Table 2 of 800-73-3 Part 1

	/******************************************************************************
	 * 
	 * NIST joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
	 * csor(3) PIV-II? (7)
	 * 
	 * From: Namespace Management for Personal Identity Verification (PIV)
	 * Applications and Data Objects Special Publication 800-73 Supplementary
	 * Information
	 *****************************************************************************/
	final static String PIV_GSC_IS = CSOR + ".7";

	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CCC = new ObjectIdentifier(PIV_GSC_IS
			+ ".1.219.0");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CHUID = new ObjectIdentifier(PIV_GSC_IS
			+ ".2.48.0");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CERT_PIVAUTH = new ObjectIdentifier(
			PIV_GSC_IS + ".2.1.1");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CARDHOLDER_FINGERPRINTS = new ObjectIdentifier(
			PIV_GSC_IS + ".2.96.16");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_SECURITY_OBJECT = new ObjectIdentifier(
			PIV_GSC_IS + ".2.144.0");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CARDHOLDER_FACIAL_IMAGE = new ObjectIdentifier(
			PIV_GSC_IS + ".2.96.48");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_PRINTED_INFORMATION = new ObjectIdentifier(
			PIV_GSC_IS + ".2.48.1");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CERT_DIGSIG = new ObjectIdentifier(
			PIV_GSC_IS + ".2.1.0");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CERT_KEYMGMT = new ObjectIdentifier(
			PIV_GSC_IS + ".2.1.2");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CERT_CARDAUTH = new ObjectIdentifier(
			PIV_GSC_IS + ".2.5.0");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_DISCOVERY_OBJECT = new ObjectIdentifier(
			PIV_GSC_IS + ".2.96.80");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_KEY_HISTORY_OBJECT = new ObjectIdentifier(
			PIV_GSC_IS + ".2.96.96");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM01 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.1");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM02 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.2");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM03 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.3");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM04 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.4");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM05 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.5");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM06 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.6");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM07 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.7");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM08 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.8");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM09 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.9");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM10 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.10");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM11 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.11");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM12 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.12");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM13 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.13");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM14 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.14");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM15 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.15");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM16 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.16");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM17 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.17");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM18 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.18");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM19 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.19");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_RET_CERT_KM20 = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.20");
	/**
	 * 
	 */
	static final ObjectIdentifier PIV_CARDHOLDER_IRIS_IMAGES = new ObjectIdentifier(
			PIV_GSC_IS + ".2.16.21");

}
