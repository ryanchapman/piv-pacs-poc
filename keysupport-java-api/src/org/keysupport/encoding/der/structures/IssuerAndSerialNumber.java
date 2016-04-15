/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: IssuerAndSerialNumber.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.INTEGER;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.util.DataUtil;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *     IssuerAndSerialNumber ::= SEQUENCE {
 *       issuer Name,
 *       serialNumber CertificateSerialNumber }
 * 
 *     CertificateSerialNumber ::= INTEGER
 * </pre>
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class IssuerAndSerialNumber {

	private SEQUENCE iasn = new SEQUENCE();
	private ASN1Object issuer = new ASN1Object();
	private ASN1Object sn = new ASN1Object();

	/**
	 * Constructor for IssuerAndSerialNumber.
	 * @param certificate X509Certificate
	 * @throws ASN1Exception
	 */
	public IssuerAndSerialNumber(X509Certificate certificate) throws ASN1Exception {
		try {
			this.issuer = new SEQUENCE(certificate.getIssuerX500Principal().getEncoded());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.sn = new INTEGER(certificate.getSerialNumber());
		this.encode();
	}
	
	/**
	 * Constructor for IssuerAndSerialNumber.
	 * @param encoded ASN1Object
	 * @throws ASN1Exception
	 */
	public IssuerAndSerialNumber(ASN1Object encoded) throws ASN1Exception {
		this.iasn = new SEQUENCE(encoded);
		this.decode();
	}

	/**
	 * Constructor for IssuerAndSerialNumber.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public IssuerAndSerialNumber(byte[] encoded) throws ASN1Exception {
		try {
			this.iasn = new SEQUENCE(encoded);
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
			en = ASN1Factory.decodeASN1Object(this.iasn.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.issuer = en.nextElement();
			this.sn = en.nextElement();
		}
	}

	/**
	 * Method encode.
	 * @throws ASN1Exception
	 */
	private void encode() throws ASN1Exception {
		SEQUENCE tmpseq = new SEQUENCE();
		tmpseq.addComponent(this.issuer);
		tmpseq.addComponent(this.sn);
		this.iasn = tmpseq;
	}

	/**
	 * Method getBytes.
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.iasn.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.iasn;
	}

	/**
	 * Method getIssuerName.
	 * @return X500Principal
	 */
	public X500Principal getIssuerName() {
		return new X500Principal(this.issuer.getBytes());
	}

	/**
	 * Method getIssuerSerial.
	 * @return BigInteger
	 * @throws TLVEncodingException
	 */
	public BigInteger getIssuerSerial() throws TLVEncodingException {
		return new INTEGER(this.sn.getBytes()).getIntegerValue();
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("SEQUENCE {\n");
		sb.append("\t" + this.getIssuerName().toString() + ",\n");
		try {
			sb.append("\t"
					+ DataUtil.byteArrayToString(this.getIssuerSerial()
							.toByteArray()) + "\n");
		} catch (TLVEncodingException e) {
			e.printStackTrace();
		}
		sb.append("}\n");
		return sb.toString();
	}
}
