/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: FASCN.java 8 2013-08-28 20:26:01Z grandamp@gmail.com $
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
 * @author Russ Davis (Original implementation in C) 
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 8 $
 * Last changed: $LastChangedDate: 2013-08-28 14:26:01 -0600 (Wed, 28 Aug 2013) $
 *****************************************************************************/

package org.keysupport.nist80073.datamodel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.BitSet;

import org.keysupport.util.DataUtil;

/**
 * @author tejohnson
 * @version $Revision: 8 $
 */
public class FASCN {

	/**
	 * Field debug.
	 */
	private static boolean debug = false;

	/*************************************************************************
	 * ANSI/ISO BCD Data Format Constants
	 * 
	 * The ANSI/ISO BCD format is 5 bit, 4 data bits + 1 parity bit (odd). The
	 * data is read least significant bit first. The character set contains 16
	 * characters, 10 alphanumeric, 3 framing/field characters and 3
	 * control/special characters.
	 * 
	 *************************************************************************/

	/**
	 * 
	 */
	public static final byte bcd_zero = 0x01; // 00001 0x00 0
	/**
	 * 
	 */
	public static final byte bcd_one = 0x10; // 10000 0x01 1
	/**
	 * 
	 */
	public static final byte bcd_two = 0x08; // 01000 0x02 2
	/**
	 * 
	 */
	public static final byte bcd_three = 0x19; // 11001 0x03 3
	/**
	 * 
	 */
	public static final byte bcd_four = 0x04; // 00100 0x04 4
	/**
	 * 
	 */
	public static final byte bcd_five = 0x15; // 10101 0x05 5
	/**
	 * 
	 */
	public static final byte bcd_six = 0x0d; // 01101 0x06 6
	/**
	 * 
	 */
	public static final byte bcd_seven = 0x1c; // 11100 0x07 7
	/**
	 * 
	 */
	public static final byte bcd_eight = 0x02; // 00010 0x08 8
	/**
	 * 
	 */
	public static final byte bcd_nine = 0x13; // 10011 0x09 9
	/**
	 * 
	 */
	public static final byte bcd_colon = 0x0b; // 01011 0x0a :
	/**
	 * 
	 */
	public static final byte bcd_ss = 0x1a; // 11010 0x0b ;
	/**
	 * 
	 */
	public static final byte bcd_less = 0x07; // 00111 0x0c <
	/**
	 * 
	 */
	public static final byte bcd_fs = 0x16; // 10110 0x0d =
	/**
	 * 
	 */
	public static final byte bcd_grtr = 0x0e; // 01110 0x0e >
	/**
	 * 
	 */
	public static final byte bcd_es = 0x1f; // 11111 0x0f ?

	// Agency Code
	/**
	 * Field ac.
	 */
	private byte[] ac = { bcd_zero, bcd_zero, bcd_zero, bcd_zero }; // 4 digits

	// System Code
	/**
	 * Field sc.
	 */
	private byte[] sc = { bcd_zero, bcd_zero, bcd_zero, bcd_zero }; // 4 digits

	// Credential Number
	/**
	 * Field cn.
	 */
	private byte[] cn = { bcd_zero, bcd_zero, bcd_zero, bcd_zero, bcd_zero,
			bcd_zero }; // 6 digits

	// Credential Series
	/**
	 * Field cs.
	 */
	private byte cs = bcd_one; // 1 digit

	// Individual Credential Issue - Recommended '1' always
	/**
	 * Field ici.
	 */
	private byte ici = bcd_zero; // 1 digit;

	// Person Identifier
	/**
	 * Field pi.
	 */
	private byte[] pi = { bcd_zero, bcd_zero, bcd_zero, bcd_zero, bcd_zero,
			bcd_zero, bcd_zero, bcd_zero, bcd_zero, bcd_zero }; // 10 digits

	// Organizational Category
	/**
	 * Field oc.
	 */
	private byte oc = bcd_zero; // 1 digit

	/**
	 * 
	 */
	public static byte FEDERAL_GOVERNMENT_AGENCY = bcd_one;
	/**
	 * 
	 */
	public static byte STATE_GOVERNMENT_AGENCY = bcd_two;
	/**
	 * 
	 */
	public static byte COMMERCIAL_ENTERPRISE = bcd_three;
	/**
	 * 
	 */
	public static byte FOREIGN_GOVERNMENT = bcd_four;

	// Organizational Identifier
	/**
	 * Field oi.
	 */
	private byte[] oi = { bcd_zero, bcd_zero, bcd_zero, bcd_zero }; // 4 digits

	// Person/Organization Association Category
	/**
	 * Field poa.
	 */
	private byte poa = bcd_zero; // 1 byte

	/**
	 * 
	 */
	public static byte EMPLOYEE = bcd_one;
	/**
	 * 
	 */
	public static byte CIVIL = bcd_two;
	/**
	 * 
	 */
	public static byte EXECUTIVE_STAFF = bcd_three;
	/**
	 * 
	 */
	public static byte UNIFORMED_SERVICE = bcd_four;
	/**
	 * 
	 */
	public static byte CONTRACTOR = bcd_five;
	/**
	 * 
	 */
	public static byte ORGANIZATIONAL_AFFILIATE = bcd_six;
	/**
	 * 
	 */
	public static byte ORGANIZATIONAL_BENEFICIARY = bcd_seven;

	// Longitudal Redundancy Check digit
	// private byte lrc = zero; // 1 digit

	/**
	 * Field fascn.
	 */
	private byte[] fascn;
	/**
	 * Field dfascn.
	 */
	private byte[] dfascn;

	/**
	 * @param ba
	
	 * @throws IOException */
	public FASCN(byte[] ba) throws IOException {
		this.fascn = ba;
		decodeFASCN(ba);
	}

	/**
	 * @param agencyCode
	 * @param systemCode
	 * @param credentialNumber
	 * @param credentialSeries
	 * @param individualCredentialIssue
	 * @param personIdentifier
	 * @param organizationalCategory
	 * @param organizationalIdentifier
	 * @param associationCategory
	
	 * @throws IOException */
	public FASCN(String agencyCode, String systemCode, String credentialNumber,
			String credentialSeries, String individualCredentialIssue,
			String personIdentifier, String organizationalCategory,
			String organizationalIdentifier, String associationCategory)
			throws IOException {
		setAgencyCode(agencyCode);
		setSystemCode(systemCode);
		setCredentialNumber(credentialNumber);
		setCredentialSeries(credentialSeries);
		setIndividualCredentialIssue(individualCredentialIssue);
		setPersonIdentifier(personIdentifier);
		setOrganizationalCategory(organizationalCategory);
		setOrganizationalIdentifier(organizationalIdentifier);
		setAssociationCategory(associationCategory);
		encodeFASCN();
	}

	/**
	 * Method bitSetToByteArray.
	 * @param bitset BitSet
	
	 * @return byte[] */
	private static byte[] bitSetToByteArray(BitSet bitset) {
		ByteArrayOutputStream ba = new ByteArrayOutputStream();
		int current_bit = 0;
		if (debug) {
			System.out.println("BitSet is " + bitset.size() + " bits long");
		}
		// Loop through the BitSet and construct individual bytes, placing thm
		// in a ByteArray
		for (int i = 0; i < 25; i++) {
			byte current_byte = 0x00;
			for (int j = 0; j <= 7; j++) {
				if (bitset.get(current_bit)) {
					switch (j) {
					case 0: {
						current_byte |= 0x80;
						break;
					}
					case 1: {
						current_byte |= 0x40;
						break;
					}
					case 2: {
						current_byte |= 0x20;
						break;
					}
					case 3: {
						current_byte |= 0x10;
						break;
					}
					case 4: {
						current_byte |= 0x08;
						break;
					}
					case 5: {
						current_byte |= 0x04;
						break;
					}
					case 6: {
						current_byte |= 0x02;
						break;
					}
					case 7: {
						current_byte |= 0x01;
						break;
					}
					}
				}
				current_bit++;
			}
			ba.write(current_byte);
		}
		return ba.toByteArray();
	}

	/**
	 * Method decodeFASCN.
	 * @param ba byte[]
	 * @throws IOException
	 */
	@SuppressWarnings("unqualified-field-access")
	private void decodeFASCN(byte[] ba) throws IOException {

		ByteArrayOutputStream raw_fascn = new ByteArrayOutputStream();
		raw_fascn.write(ba);
		byte[] byte_fascn = raw_fascn.toByteArray();

		if (debug) {
			System.out.println(byte_fascn.length + " bytes: "
					+ DataUtil.byteArrayToString(byte_fascn));
		}

		// Convert the 200 bit value into a 40 byte array
		BitSet pre_fascn = new BitSet();
		// if (debug) { System.out.println("BitSet is " + pre_fascn.size() +
		// " bits long"); }
		int current_bit = 0;
		for (int i = 0; i < byte_fascn.length; i++) {
			// loop through each byte in the array to get each BCD
			// Shift each byte right three places
			int temp_byte = byte_fascn[i];
			int mask = 0x80;
			for (int j = 0; j <= 7; j++) {
				// get the last 5 values, adding them to the bitset
				if ((temp_byte & mask) == mask) {
					pre_fascn.set(current_bit);
					// if (debug) { System.out.println("Bit " + current_bit +
					// " = 1"); }
				}
				temp_byte <<= 1;
				current_bit++;
				// if (debug) { System.out.println("BitSet is " +
				// pre_fascn.size() + " bits long"); }
			}
		}

		raw_fascn.reset();
		// Loop through the 200 bits, extract 5 at a time, then convert to a
		// byte array
		for (int j = 0; j < 200; j += 5) {
			byte current_byte = 0x00;
			BitSet bitset = pre_fascn.get(j, j + 5);
			current_bit = 0;
			for (int k = 0; k < 5; k++) {
				if (bitset.get(current_bit)) {
					switch (k) {
					case 0: {
						current_byte |= 0x10;
						break;
					}
					case 1: {
						current_byte |= 0x08;
						break;
					}
					case 2: {
						current_byte |= 0x04;
						break;
					}
					case 3: {
						current_byte |= 0x02;
						break;
					}
					case 4: {
						current_byte |= 0x01;
						break;
					}
					}
				}
				current_bit++;
			}
			raw_fascn.write(current_byte);
		}

		this.dfascn = raw_fascn.toByteArray();
		if (debug) {
			System.out.println(this.dfascn.length + " bytes: "
					+ DataUtil.byteArrayToString(this.dfascn));
		}

		/****************************************************************************************************
		 * --------------------------------------------------------------------
		 * ------------------------------ - Field -| ss | ac | fs | sc | fs | cn
		 * | fs | cs | fs | ici | fs | pi | oc | oi | poa | es | lrc |
		 * ----------
		 * ------------------------------------------------------------
		 * ---------------------------- - Digits | 1 | 4 | 1 | 4 | 1 | 6 | 1 | 1
		 * | 1 | 1 | 1 | 10 | 1 | 4 | 1 | 1 | 1 |
		 * --------------------------------
		 * ------------------------------------------------------------------
		 ****************************************************************************************************/

		// Agency Code
		ac[0] = dfascn[1];
		ac[1] = dfascn[2];
		ac[2] = dfascn[3];
		ac[3] = dfascn[4];
		if (debug) {
			System.out.println("AC:\t" + translateS(rtranslate(ac)));
		}

		// System Code
		sc[0] = dfascn[6];
		sc[1] = dfascn[7];
		sc[2] = dfascn[8];
		sc[3] = dfascn[9];
		if (debug) {
			System.out.println("SC:\t" + translateS(rtranslate(sc)));
		}

		// Credential Number
		cn[0] = dfascn[11];
		cn[1] = dfascn[12];
		cn[2] = dfascn[13];
		cn[3] = dfascn[14];
		cn[4] = dfascn[15];
		cn[5] = dfascn[16];
		if (debug) {
			System.out.println("CN:\t" + translateS(rtranslate(cn)));
		}

		// Credential Series
		cs = dfascn[18];
		if (debug) {
			System.out.println("CS:\t" + translateS(rtranslate(cs)));
		}

		// Individual Credential Issue - Recommended '1' always
		ici = dfascn[20];
		if (debug) {
			System.out.println("ICI:\t" + translateS(rtranslate(ici)));
		}

		// Person Identifier
		pi[0] = dfascn[22];
		pi[1] = dfascn[23];
		pi[2] = dfascn[24];
		pi[3] = dfascn[25];
		pi[4] = dfascn[26];
		pi[5] = dfascn[27];
		pi[6] = dfascn[28];
		pi[7] = dfascn[29];
		pi[8] = dfascn[30];
		pi[9] = dfascn[31];
		if (debug) {
			System.out.println("PI:\t" + translateS(rtranslate(pi)));
		}

		// Organizational Category
		oc = dfascn[32];
		if (debug) {
			System.out.println("OC:\t" + translateS(rtranslate(oc)));
		}

		// Organizational Identifier
		oi[0] = dfascn[33];
		oi[1] = dfascn[34];
		oi[2] = dfascn[35];
		oi[3] = dfascn[36];
		if (debug) {
			System.out.println("OI:\t" + translateS(rtranslate(oi)));
		}

		// Person/Organization Association Categroy
		poa = dfascn[37];
		if (debug) {
			System.out.println("POA:\t" + translateS(rtranslate(poa)));
		}

	}

	/**
	 * Method encodeFASCN.
	
	 * @throws IOException */
	@SuppressWarnings("unqualified-field-access")
	private void encodeFASCN() throws IOException {

		/****************************************************************************************************
		 * --------------------------------------------------------------------
		 * ------------------------------ - Field -| ss | ac | fs | sc | fs | cn
		 * | fs | cs | fs | ici | fs | pi | oc | oi | poa | es | lrc |
		 * ----------
		 * ------------------------------------------------------------
		 * ---------------------------- - Digits | 1 | 4 | 1 | 4 | 1 | 6 | 1 | 1
		 * | 1 | 1 | 1 | 10 | 1 | 4 | 1 | 1 | 1 |
		 * --------------------------------
		 * ------------------------------------------------------------------
		 ****************************************************************************************************/

		ByteArrayOutputStream raw_fascn = new ByteArrayOutputStream();
		raw_fascn.write(bcd_ss);
		raw_fascn.write(ac);
		raw_fascn.write(bcd_fs);
		raw_fascn.write(sc);
		raw_fascn.write(bcd_fs);
		raw_fascn.write(cn);
		raw_fascn.write(bcd_fs);
		raw_fascn.write(cs);
		raw_fascn.write(bcd_fs);
		raw_fascn.write(ici);
		raw_fascn.write(bcd_fs);
		raw_fascn.write(pi);
		raw_fascn.write(oc);
		raw_fascn.write(oi);
		raw_fascn.write(poa);
		raw_fascn.write(bcd_es);
		byte[] byte_fascn = raw_fascn.toByteArray();

		if (debug) {
			System.out.println(byte_fascn.length + " bytes: "
					+ DataUtil.byteArrayToString(byte_fascn));
		}
		// Convert the 39 byte array to a 195 bit value in a BitSet
		BitSet pre_fascn = new BitSet(195);
		int current_bit = 0;
		for (int i = 0; i < byte_fascn.length; i++) {
			// loop through each byte in the array to get each BCD
			// Shift each byte left three places
			int temp_byte = byte_fascn[i];
			int mask = 0x80;
			temp_byte <<= 3;
			for (int j = 0; j <= 4; j++) {
				// get the last 5 values, adding them to the bitset
				if ((temp_byte & mask) == mask) {
					pre_fascn.set(current_bit);
					if (debug) {
						System.out.println("Bit " + current_bit + " = 1");
					}
				}
				temp_byte <<= 1;
				current_bit++;
			}
		}
		if (debug) {
			System.out.println(pre_fascn.toString());
		}
		if (debug) {
			System.out.println("Before LRC BitSet is " + pre_fascn.size()
					+ " bits long");
		}
		// loop through the bitset to perform the LRC
		BitSet bcd = new BitSet(5);
		for (int marker = 0; marker < 195; marker += 5) {
			bcd.xor(pre_fascn.get(marker, marker + 5));
		}
		if (debug) {
			System.out.println(bcd.toString());
		}
		// Add LRC value to the fascn we have created
		for (int append = 195; append <= 199; append++) {
			if (bcd.get(append - 195)) {
				pre_fascn.set(append);
			}
		}
		if (debug) {
			System.out.println(pre_fascn.toString());
		}
		this.fascn = bitSetToByteArray(pre_fascn);
		if (debug) {
			System.out.println(this.fascn.length + " bytes: "
					+ DataUtil.byteArrayToString(this.fascn));
		}
	}

	/**
	
	 * @return String representing a numeric Agency Code */
	public String getAgencyCode() {
		return translateS(rtranslate(this.ac));
	}

	/**
	 * Method getAssociationCategory.
	
	 * @return String */
	public String getAssociationCategory() {
		return translateS(rtranslate(this.poa));
	}

	/**
	
	 * @return String representing a numeric Credential Number */
	public String getCredentialNumber() {
		return translateS(rtranslate(this.cn));
	}

	/**
	
	 * @return String representing a Credential Series */
	public String getCredentialSeries() {
		return translateS(rtranslate(this.cs));
	}

	/**
	
	 * @return String representing Individual Credential Issue */
	public String getIndividualCredentialIssue() {
		return translateS(rtranslate(this.ici));
	}

	/**
	 * Method getOrganizationalCategory.
	
	 * @return String */
	public String getOrganizationalCategory() {
		return translateS(rtranslate(this.oc));
	}

	/**
	 * Method getOrganizationalIdentifier.
	
	 * @return String */
	public String getOrganizationalIdentifier() {
		return translateS(rtranslate(this.oi));
	}

	/**
	 * Method getPersonIdentifier.
	
	 * @return String */
	public String getPersonIdentifier() {
		return translateS(rtranslate(this.pi));
	}

	/**
	
	 * @return String representing a numeric System Code */
	public String getSystemCode() {
		return translateS(rtranslate(this.sc));
	}

	/**
	 * Method rtranslate.
	 * @param digit byte
	
	 * @return byte */
	private static byte rtranslate(byte digit) {
		switch (digit) {
		case bcd_zero: {
			return 0x00;
		}
		case bcd_one: {
			return 0x01;
		}
		case bcd_two: {
			return 0x02;
		}
		case bcd_three: {
			return 0x03;
		}
		case bcd_four: {
			return 0x04;
		}
		case bcd_five: {
			return 0x05;
		}
		case bcd_six: {
			return 0x06;
		}
		case bcd_seven: {
			return 0x07;
		}
		case bcd_eight: {
			return 0x08;
		}
		case bcd_nine: {
			return 0x09;
		}
		}
		// if we don't have a match, return a zero, although we should not get
		// here
		// if (debug) { System.out.println("Returning a ZERO!"); }
		return 0x00;
	}

	/**
	 * Method rtranslate.
	 * @param digits byte[]
	
	 * @return byte[] */
	private static byte[] rtranslate(byte[] digits) {
		ByteArrayOutputStream ba = new ByteArrayOutputStream();
		for (int i = 0; i < digits.length; i++) {
			ba.write(rtranslate(digits[i]));
		}
		return ba.toByteArray();
	}

	/**
	 * @param agencyCode
	
	 * @throws IOException */
	public void setAgencyCode(byte[] agencyCode) throws IOException {
		this.ac = agencyCode;
		encodeFASCN();
	}

	/**
	 * @param agencyCode
	
	 * @throws IOException */
	public void setAgencyCode(String agencyCode) throws IOException {
		if (debug) {
			System.out.println("Agency Code is: " + agencyCode);
		}
		this.ac = translate(agencyCode);
		encodeFASCN();
	}

	/**
	 * Method setAssociationCategory.
	 * @param associationCategory String
	
	 * @throws IOException */
	public void setAssociationCategory(String associationCategory)
			throws IOException {
		if (debug) {
			System.out.println("Association Category is: "
					+ associationCategory);
		}
		this.poa = translate(associationCategory.charAt(0));
		encodeFASCN();
	}

	/**
	 * @param credentialNumber
	
	 * @throws IOException */
	public void setCredentialNumber(String credentialNumber) throws IOException {
		if (debug) {
			System.out.println("Credential Number is: " + credentialNumber);
		}
		this.cn = translate(credentialNumber);
		encodeFASCN();
	}

	/**
	 * @param credentialSeries
	
	 * @throws IOException */
	public void setCredentialSeries(String credentialSeries) throws IOException {
		if (debug) {
			System.out.println("Credential Series is: " + credentialSeries);
		}
		this.cs = translate(credentialSeries.charAt(0));
		encodeFASCN();
	}

	/**
	 * @param individualCredentialIssue
	
	 * @throws IOException */
	public void setIndividualCredentialIssue(String individualCredentialIssue)
			throws IOException {
		if (debug) {
			System.out.println("Individual Credential Issue is: "
					+ individualCredentialIssue);
		}
		this.ici = translate(individualCredentialIssue.charAt(0));
		encodeFASCN();
	}

	/**
	 * Method setOrganizationalCategory.
	 * @param organizationalCategory String
	
	 * @throws IOException */
	public void setOrganizationalCategory(String organizationalCategory)
			throws IOException {
		if (debug) {
			System.out.println("Organizational Category is: "
					+ organizationalCategory);
		}
		this.oc = translate(organizationalCategory.charAt(0));
		encodeFASCN();
	}

	/**
	 * Method setOrganizationalIdentifier.
	 * @param organizationalIdentifier String
	
	 * @throws IOException */
	public void setOrganizationalIdentifier(String organizationalIdentifier)
			throws IOException {
		if (debug) {
			System.out.println("Organizational Identifier is: "
					+ organizationalIdentifier);
		}
		this.oi = translate(organizationalIdentifier);
		encodeFASCN();
	}

	/**
	 * @param personIdentifier
	
	 * @throws IOException */
	public void setPersonIdentifier(String personIdentifier) throws IOException {
		if (debug) {
			System.out.println("Person Identifier is: " + personIdentifier);
		}
		this.pi = translate(personIdentifier);
		encodeFASCN();
	}

	/**
	 * @param systemCode
	
	 * @throws IOException */
	public void setSystemCode(String systemCode) throws IOException {
		if (debug) {
			System.out.println("System Code is: " + systemCode);
		}
		this.sc = translate(systemCode);
		encodeFASCN();
	}

	/**
	 * Method toByteArray.
	
	 * @return byte[] */
	public byte[] toByteArray() {
		return this.fascn;
	}

	/**
	 * Method toString.
	
	 * @return String */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("FASCN Value:\n");
		sb.append("AC:\t" + translateS(rtranslate(this.ac)) + "\n");
		sb.append("SC:\t" + translateS(rtranslate(this.sc)) + "\n");
		sb.append("CN:\t" + translateS(rtranslate(this.cn)) + "\n");
		sb.append("CS:\t" + translateS(rtranslate(this.cs)) + "\n");
		sb.append("ICI:\t" + translateS(rtranslate(this.ici)) + "\n");
		sb.append("PI:\t" + translateS(rtranslate(this.pi)) + "\n");
		sb.append("OC:\t" + translateS(rtranslate(this.oc)) + "\n");
		sb.append("OI:\t" + translateS(rtranslate(this.oi)) + "\n");
		sb.append("POA:\t" + translateS(rtranslate(this.poa)));
		return sb.toString();
	}

	/**
	 * Method translate.
	 * @param digit char
	
	 * @return byte */
	private static byte translate(char digit) {
		if (debug) {
			System.out.println("Digit to translate is " + digit);
		}
		switch (digit) {
		case '0': {
			return bcd_zero;
		}
		case '1': {
			return bcd_one;
		}
		case '2': {
			return bcd_two;
		}
		case '3': {
			return bcd_three;
		}
		case '4': {
			return bcd_four;
		}
		case '5': {
			return bcd_five;
		}
		case '6': {
			return bcd_six;
		}
		case '7': {
			return bcd_seven;
		}
		case '8': {
			return bcd_eight;
		}
		case '9': {
			return bcd_nine;
		}
		}
		// if we don't have a match, return a zero, although we should not get
		// here
		// if (debug) { System.out.println("Returning a ZERO!"); }
		return bcd_zero;
	}

	/**
	 * Method translate.
	 * @param digits String
	
	 * @return byte[] */
	private static byte[] translate(String digits) {
		ByteArrayOutputStream ba = new ByteArrayOutputStream();
		for (int i = 0; i < digits.length(); i++) {
			ba.write(translate(digits.charAt(i)));
		}
		return ba.toByteArray();
	}

	/**
	 * Method translateS.
	 * @param digit byte
	
	 * @return String */
	private static String translateS(byte digit) {
		return Integer.valueOf(digit).toString();
	}

	/**
	 * Method translateS.
	 * @param digits byte[]
	
	 * @return String */
	private static String translateS(byte[] digits) {
		StringBuffer sb = new StringBuffer(digits.length);
		for (int i = 0; i < digits.length; i++) {
			sb.append(translateS(digits[i]));
		}
		return sb.toString();
	}

}