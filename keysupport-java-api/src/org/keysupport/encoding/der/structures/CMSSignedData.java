/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CMSSignedData.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.encoding.der.structures;

import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.CON_SPEC;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.der.ObjectIdentifier;

/**
 * This class represents a Cryptographic Message Syntax (CMS) as defined in RFC
 * 3852. It is only capable of containing a SignedData object, with requirements
 * defined in FIPS 201-1, Section 4.2.2 "Asymmetric Signature Field in CHUID"
 * [Pages 30-31].<br>
 * <br>
 * 
 * <pre>
 * "This standard requires inclusion of the Asymmetric Signature field 
 * in the CHUID container. The Asymmetric Signature data element of the 
 * PIV CHUID shall be encoded as a Cryptographic Message Syntax (CMS) 
 * external digital signature, as defined in RFC 3852 [RFC3852]. The 
 * digital signature shall be computed over the entire contents of the 
 * CHUID, excluding the Asymmetric Signature field. Algorithm and key 
 * size requirements for the asymmetric signature are detailed in [SP800-78].
 * 
 * The issuer asymmetric signature file is implemented as a SignedData 
 * Type, as specified in [RFC3852], and shall include the following information:
 * 
 * 	+ The message shall include a version field specifying version v3 
 * 	+ The digestAlgorithms field shall be as specified in [SP800-78]
 * 	+ The encapContentInfo shall: 
 * 		– Specify an eContentType of id-PIV-CHUIDSecurityObject 
 * 		– Omit the eContent field 
 * 	+ The certificates field shall include only a single X.509 certificate 
 *        which can be used to verify the  signature in the SignerInfo field 
 * 	+ The crls field shall be omitted 
 * 	+ signerInfos shall be present and include only a single SignerInfo
 * 	+ The SignerInfo shall: 
 * 		– Use the issuerAndSerialNumber choice for SignerIdentifier
 * 		– Specify a digestAlgorithm in accordance with [SP800-78]
 * 		– Include, at a minimum, the following signed attributes: 
 * 			• A MessageDigest attribute containing the hash computed over 
 * 			  the concatenated contents of the CHUID, excluding the 
 * 			  asymmetric signature field
 * 			• A pivSigner-DN attribute containing the subject name that 
 * 			  appears in the PKI certificate for the entity that signed 
 * 			  the CHUID 
 * 		– Include the digital signature."
 * </pre>
 * 
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 * 
 *    The following object identifier identifies the content information
 *    type:
 * 
 *    id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *       us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
 * 
 * The CMS associates a content type identifier with a content.  The
 * syntax MUST have ASN.1 type ContentInfo:
 * 
 *    ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content [0] EXPLICIT ANY DEFINED BY contentType }
 * 
 *    ContentType ::= OBJECT IDENTIFIER
 *    
 * The fields of ContentInfo have the following meanings:
 * 
 *    contentType indicates the type of the associated content.  It is
 *    an object identifier; it is a unique string of integers assigned
 *    by an authority that defines the content type.
 *    
 *    content is the associated content.  The type of content can be
 *    determined uniquely by contentType.  Content types for data,
 *    signed-data, enveloped-data, digested-data, encrypted-data, and
 *    authenticated-data are defined in this document.  If additional
 *    content types are defined in other documents, the ASN.1 type
 *    defined SHOULD NOT be a CHOICE type.
 *    
 *  ...
 * 
 *  The following object identifier identifies the signed-data content
 *  type:
 * 
 *      id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *         us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
 * 
 *  The signed-data content type shall have ASN.1 type SignedData:
 * 
 *     SignedData ::= SEQUENCE {
 *      version CMSVersion,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      encapContentInfo EncapsulatedContentInfo,
 *      certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *      signerInfos SignerInfos }
 * 
 *    DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * 
 *    SignerInfos ::= SET OF SignerInfo
 * 
 *  The fields of type SignedData have the following meanings:
 * 
 *    version is the syntax version number.  The appropriate value
 *    depends on certificates, eContentType, and SignerInfo.  The
 *    version MUST be assigned as follows:
 * 
 *       IF ((certificates is present) AND
 *          (any certificates with a type of other are present)) OR
 *          ((crls is present) AND
 *          (any crls with a type of other are present))
 *       THEN version MUST be 5
 *       ELSE
 *          IF (certificates is present) AND
 *             (any version 2 attribute certificates are present)
 *          THEN version MUST be 4
 *          ELSE
 *             IF ((certificates is present) AND
 *                (any version 1 attribute certificates are present)) OR
 *                (any SignerInfo structures are version 3) OR
 *                (encapContentInfo eContentType is other than id-data)
 *             THEN version MUST be 3
 *             ELSE version MUST be 1
 * </pre>
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class CMSSignedData {

	private SEQUENCE cms = new SEQUENCE();
	private ASN1Object type = new ASN1Object();
	private ASN1Object content = new ASN1Object();

	public CMSSignedData() {
	}

	/**
	 * Constructor for CMSSignedData.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public CMSSignedData(byte[] encoded) throws ASN1Exception {
		try {
			this.cms = new SEQUENCE(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.decode();
	}

	/**
	 * Method decode.
	 * @throws ASN1Exception
	 */
	private void decode() throws ASN1Exception {
		Enumeration<ASN1Object> en;
		try {
			en = ASN1Factory.decodeASN1Object(this.cms.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.type = en.nextElement();
			ASN1Object cobj = en.nextElement();
			if (cobj.isA(new CON_SPEC(0).CON_SPEC)) {
				this.content = cobj;
			} else {
				throw new ASN1Exception("Malformed Content in SignedData.");
			}
		}
	}

	/**
	 * Method encode.
	 * @throws ASN1Exception
	 */
	private void encode() throws ASN1Exception {
		SEQUENCE tmpseq = new SEQUENCE();
		tmpseq.addComponent(this.type);
		tmpseq.addComponent(this.content);
		this.cms = tmpseq;
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.cms.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.cms;
	}


	/**
	 * Method getContentType.
	 * @return ObjectIdentifier
	 */
	public ObjectIdentifier getContentType() {
		return new ObjectIdentifier(this.type.getValue());
	}

	/**
	 * Method getSignedData.
	 * @return SignedData
	 * @throws ASN1Exception
	 */
	public SignedData getSignedData() throws ASN1Exception {
		CON_SPEC signed_data;
		try {
			signed_data = new CON_SPEC(this.content);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		return new SignedData(signed_data.getValue());
	}
	
	/**
	 * Method setContentType.
	 * @param type ASN1Object
	 * @throws ASN1Exception
	 */
	public void setContentType(ASN1Object type) throws ASN1Exception {
		this.type = type;
		this.encode();
	}

	/**
	 * Method setSignedData.
	 * @param content ASN1Object
	 * @throws ASN1Exception
	 */
	public void setSignedData(ASN1Object content) throws ASN1Exception {
		this.content = content;
		this.encode();
	}
	
}
