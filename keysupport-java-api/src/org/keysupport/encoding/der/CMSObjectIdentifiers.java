/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CMSObjectIdentifiers.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.encoding.der;


/**
 */
public interface CMSObjectIdentifiers {

	static final String PKCS = "1.2.840.113549.1";
	static final String PKCS7 = PKCS + ".7";
	static final String PKCS9 = PKCS + ".9";

	/**
	 * Content Type Identifiers
	 */

	/**
	 * id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
	 */
	static final ObjectIdentifier id_ct_contentInfo = new ObjectIdentifier(
			PKCS9 + ".16.1.6");

	/**
	 * id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs7(7) 1 }
	 */
	static final ObjectIdentifier id_data = new ObjectIdentifier(PKCS7 + ".1");

	/**
	 * id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs7(7) 2 }
	 */
	static final ObjectIdentifier id_signedData = new ObjectIdentifier(PKCS7
			+ ".2");

	/**
	 * id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs7(7) 3 }
	 */
	static final ObjectIdentifier id_envelopedData = new ObjectIdentifier(PKCS7
			+ ".3");

	/**
	 * id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)us(840)
	 * rsadsi(113549) pkcs(1) pkcs7(7) 5 }
	 */
	static final ObjectIdentifier id_digestedData = new ObjectIdentifier(PKCS7
			+ ".5");

	/**
	 * id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs7(7) 6 }
	 */
	static final ObjectIdentifier id_encryptedData = new ObjectIdentifier(PKCS7
			+ ".6");

	/**
	 * id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 2 }
	 */
	static final ObjectIdentifier id_ct_authData = new ObjectIdentifier(PKCS9
			+ ".16.1.2");

	/**
	 * Attribute Identifiers
	 */

	/**
	 * id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs9(9) 3 }
	 */
	static final ObjectIdentifier id_contentType = new ObjectIdentifier(PKCS9
			+ ".3");

	/**
	 * id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs9(9) 4 }
	 */
	static final ObjectIdentifier id_messageDigest = new ObjectIdentifier(PKCS9
			+ ".4");

	/**
	 * id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs9(9) 5 }
	 */
	static final ObjectIdentifier id_signingTime = new ObjectIdentifier(PKCS9
			+ ".5");

	/**
	 * id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
	 * rsadsi(113549) pkcs(1) pkcs9(9) 6 }
	 */
	static final ObjectIdentifier id_countersignature = new ObjectIdentifier(
			PKCS9 + ".6");

}
