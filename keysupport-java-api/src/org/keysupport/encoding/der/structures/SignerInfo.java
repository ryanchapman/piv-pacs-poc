/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: SignerInfo.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
import java.util.Vector;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.asn1.SET;
import org.keysupport.encoding.TLVEncodingException;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *    SignerInfo ::= SEQUENCE {
 *      version CMSVersion,
 *      sid SignerIdentifier,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *      signatureAlgorithm SignatureAlgorithmIdentifier,
 *      signature SignatureValue,
 *      unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 * 
 *    SignerIdentifier ::= CHOICE {
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      subjectKeyIdentifier [0] SubjectKeyIdentifier }
 * 
 *    SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * 
 *    UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * 
 *    Attribute ::= SEQUENCE {
 *      attrType OBJECT IDENTIFIER,
 *      attrValues SET OF AttributeValue }
 * 
 *    AttributeValue ::= ANY
 * 
 *    SignatureValue ::= OCTET STRING
 * </pre>
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class SignerInfo {

	private SEQUENCE si = new SEQUENCE();
	private ASN1Object version = new ASN1Object();
	private ASN1Object sid = new ASN1Object();
	private ASN1Object aldig = new ASN1Object();
	private ASN1Object sattr = new ASN1Object();
	private ASN1Object sigalg = new ASN1Object();
	private ASN1Object sig = new ASN1Object();
	private ASN1Object usattr = new ASN1Object();

	public SignerInfo() {
	}

	/**
	 * Constructor for SignerInfo.
	 * @param encoded ASN1Object
	 * @throws ASN1Exception
	 */
	public SignerInfo(ASN1Object encoded) throws ASN1Exception {
		this.si = new SEQUENCE(encoded);
		this.decode();
	}

	/**
	 * Constructor for SignerInfo.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public SignerInfo(byte[] encoded) throws ASN1Exception {
		try {
			this.si = new SEQUENCE(encoded);
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
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.si.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.setVersion(en.nextElement());
			this.setSignerIdentifier(en.nextElement());
			this.setDigestAlgID(en.nextElement());
			this.setSignedAttributes(en.nextElement());
			this.setSigAlgID(en.nextElement());
			this.setSignature(en.nextElement());
			if (en.hasMoreElements()) {
				this.setUnsignedAttributes(en.nextElement());
			}
		}
	}

	/**
	 * Method encode.
	 * @throws ASN1Exception
	 */
	private void encode() throws ASN1Exception {
		SEQUENCE tmpseq = new SEQUENCE();
		tmpseq.addComponent(this.version);
		tmpseq.addComponent(this.sid);
		tmpseq.addComponent(this.aldig);
		tmpseq.addComponent(this.sattr);
		tmpseq.addComponent(this.sigalg);
		tmpseq.addComponent(this.sig);
		if (this.usattr != null) {
			tmpseq.addComponent(this.usattr);
		}
		this.si = tmpseq;
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.si.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.si;
	}

	/**
	
	
	 * @return the aldig * @throws ASN1Exception */
	public AlgorithmIdentifier getDigestAlgID() throws ASN1Exception {
		return new AlgorithmIdentifier(this.aldig);
	}

	/**
	
	 * @return the sigalg * @throws ASN1Exception
	 */
	public AlgorithmIdentifier getSigAlgID() throws ASN1Exception {
		return new AlgorithmIdentifier(this.sigalg);
	}

	/**
	
	 * @return the sig */
	public byte[] getSignature() {
		return this.sig.getValue();
	}

	/**
	
	 * 
	 * @return The Signed Attributes as a DER encoded Byte Array, where the
	 *         IMPLICIT [0] tag has been converted to an EXPLICIT SET OF tag for
	 *         use in calculating the signature value */
	public byte[] getSignedAttrBytes() {
		// Convert IMPLICIT [0] tag to EXPLICIT SET OF tag and return
		ASN1Object implicitToSET = ASN1Factory.encodeASN1Object(new SET().SET,
				this.sattr.getValue());
		return implicitToSET.getBytes();
	}

	/**
	
	
	 * @return the sattr * @throws ASN1Exception */
	public Enumeration<Attribute> getSignedAttributes() throws ASN1Exception {
		Vector<Attribute> v = new Vector<Attribute>();
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.sattr.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		while (en.hasMoreElements()) {
			v.add(new Attribute(en.nextElement()));
		}
		return v.elements();
	}

	/**
	
	
	 * @return the sid * @throws ASN1Exception */
	public IssuerAndSerialNumber getSignerIdentifier() throws ASN1Exception {
		return new IssuerAndSerialNumber(this.sid);
	}

	/**
	
	
	 * @return the usattr * @throws ASN1Exception */
	public Enumeration<Attribute> getUnsignedAttributes() throws ASN1Exception {
		Vector<Attribute> v = new Vector<Attribute>();
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.usattr.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		while (en.hasMoreElements()) {
			v.add(new Attribute(en.nextElement()));
		}
		return v.elements();
	}

	/**
	
	 * @return the version */
	public CMSVersion getVersion() {
		return new CMSVersion(this.version);
	}

	/**
	 * @param aldig
	 *            the aldig to set
	
	 * @throws ASN1Exception  */
	public void setDigestAlgID(ASN1Object aldig) throws ASN1Exception {
		this.aldig = aldig;
		this.encode();
	}

	/**
	 * @param sigalg
	 *            the sigalg to set
	
	 * @throws ASN1Exception  */
	public void setSigAlgID(ASN1Object sigalg) throws ASN1Exception {
		this.sigalg = sigalg;
		this.encode();
	}

	/**
	 * @param sig
	 *            the sig to set
	
	 * @throws ASN1Exception  */
	public void setSignature(ASN1Object sig) throws ASN1Exception {
		this.sig = sig;
		this.encode();
	}

	/**
	 * @param sattr
	 *            the sattr to set
	
	 * @throws ASN1Exception  */
	public void setSignedAttributes(ASN1Object sattr) throws ASN1Exception {
		this.sattr = sattr;
		this.encode();
	}

	/**
	 * @param sid
	 *            the sid to set
	
	 * @throws ASN1Exception  */
	public void setSignerIdentifier(ASN1Object sid) throws ASN1Exception {
		this.sid = sid;
		this.encode();
	}

	/**
	 * @param usattr
	 *            the usattr to set
	
	 * @throws ASN1Exception  */
	public void setUnsignedAttributes(ASN1Object usattr) throws ASN1Exception {
		this.usattr = usattr;
		this.encode();
	}

	/**
	 * @param version
	 *            the version to set
	
	 * @throws ASN1Exception  */
	public void setVersion(ASN1Object version) throws ASN1Exception {
		this.version = version;
		this.encode();
	}

}
