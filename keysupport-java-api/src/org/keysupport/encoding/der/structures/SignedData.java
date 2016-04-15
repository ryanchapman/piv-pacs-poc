/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: SignedData.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
import org.keysupport.asn1.CON_SPEC;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.asn1.SET;
import org.keysupport.encoding.TLVEncodingException;

/**
 * * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *     SignedData ::= SEQUENCE {
 *      version CMSVersion,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      encapContentInfo EncapsulatedContentInfo,
 *      certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *      signerInfos SignerInfos }
 * </pre>
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class SignedData {

	private SEQUENCE sd = new SEQUENCE();
	private ASN1Object version = new ASN1Object();
	private ASN1Object dalgs = new ASN1Object();
	private ASN1Object eci = new ASN1Object();
	private ASN1Object cset = new ASN1Object();
	private ASN1Object ric = new ASN1Object();
	private ASN1Object si = new ASN1Object();

	public SignedData() {
	}

	/**
	 * Constructor for SignedData.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public SignedData(byte[] encoded) throws ASN1Exception {
		try {
			this.sd = new SEQUENCE(encoded);
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
			en = ASN1Factory.decodeASN1Object(this.sd.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.setVersion(en.nextElement());
			this.setDigestAlgIDs(en.nextElement());
			this.setEncapContentInfo(en.nextElement());
			while (en.hasMoreElements()) {
				ASN1Object cobj = en.nextElement();
				if (cobj.isA(new CON_SPEC(0).CON_SPEC)) {
					setCertificateSet(cobj);
				}
				if (cobj.isA(new CON_SPEC(1).CON_SPEC)) {
					setRevocationInfoChoices(cobj);
				}
				if (cobj.isA(new SET().SET)) {
					setSignerInfos(cobj);
				}
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
		tmpseq.addComponent(this.dalgs);
		tmpseq.addComponent(this.eci);
		tmpseq.addComponent(this.cset);
		if (this.ric != null) {
			tmpseq.addComponent(this.ric);
		}
		tmpseq.addComponent(this.si);
		this.sd = tmpseq;
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.sd.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.sd;
	}

	/**
	 * Method getCertificateSet.
	 * @return Enumeration<CertificateChoices>
	 * @throws ASN1Exception
	 */
	public Enumeration<CertificateChoices> getCertificateSet()
			throws ASN1Exception {
		Vector<CertificateChoices> v = new Vector<CertificateChoices>();
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.cset.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		while (en.hasMoreElements()) {
			v.add(new CertificateChoices(en.nextElement()));
		}
		return v.elements();
	}

	/**
	 * Method getDigestAlgIDs.
	 * @return AlgorithmIdentifier
	 * @throws ASN1Exception
	 */
	public AlgorithmIdentifier getDigestAlgIDs() throws ASN1Exception {
		return new AlgorithmIdentifier(this.dalgs.getValue());
	}

	/**
	 * Method getEncapContentInfo.
	 * @return EncapsulatedContentInfo
	 * @throws ASN1Exception
	 */
	public EncapsulatedContentInfo getEncapContentInfo() throws ASN1Exception {
		return new EncapsulatedContentInfo(this.eci);
	}

	/**
	 * Method getRevocationInfoChoices.
	 * @return ASN1Object
	 */
	public ASN1Object getRevocationInfoChoices() {
		return this.ric;
	}

	/**
	 * Method getSignerInfos.
	 * @return Enumeration<SignerInfo>
	 * @throws ASN1Exception
	 */
	public Enumeration<SignerInfo> getSignerInfos() throws ASN1Exception {
		Vector<SignerInfo> v = new Vector<SignerInfo>();
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.si.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		while (en.hasMoreElements()) {
			v.add(new SignerInfo(en.nextElement()));
		}
		return v.elements();
	}

	/**
	 * Method getVersion.
	 * @return CMSVersion
	 */
	public CMSVersion getVersion() {
		return new CMSVersion(this.version);
	}

	/**
	 * Method setCertificateSet.
	 * @param cset ASN1Object
	 * @throws ASN1Exception
	 */
	public void setCertificateSet(ASN1Object cset) throws ASN1Exception {
		this.cset = cset;
		this.encode();
	}

	/**
	 * Method setDigestAlgIDs.
	 * @param dalgs ASN1Object
	 * @throws ASN1Exception
	 */
	public void setDigestAlgIDs(ASN1Object dalgs) throws ASN1Exception {
		this.dalgs = dalgs;
		this.encode();
	}

	/**
	 * Method setEncapContentInfo.
	 * @param eci ASN1Object
	 * @throws ASN1Exception
	 */
	public void setEncapContentInfo(ASN1Object eci) throws ASN1Exception {
		this.eci = eci;
		this.encode();
	}

	/**
	 * Method setRevocationInfoChoices.
	 * @param ric ASN1Object
	 * @throws ASN1Exception
	 */
	public void setRevocationInfoChoices(ASN1Object ric) throws ASN1Exception {
		this.ric = ric;
		this.encode();
	}

	/**
	 * Method setSignerInfos.
	 * @param si ASN1Object
	 * @throws ASN1Exception
	 */
	public void setSignerInfos(ASN1Object si) throws ASN1Exception {
		this.si = si;
		this.encode();
	}

	/**
	 * Method setVersion.
	 * @param version ASN1Object
	 * @throws ASN1Exception
	 */
	public void setVersion(ASN1Object version) throws ASN1Exception {
		this.version = version;
		this.encode();
	}

}
