/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CertificateChoices.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.CON_SPEC;
import org.keysupport.encoding.TLVEncodingException;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *    CertificateChoices ::= CHOICE {
 *     certificate Certificate,
 *     extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
 *     v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
 *     v2AttrCert [2] IMPLICIT AttributeCertificateV2,
 *     other [3] IMPLICIT OtherCertificateFormat }
 * 
 *    OtherCertificateFormat ::= SEQUENCE {
 *     otherCertFormat OBJECT IDENTIFIER,
 *     otherCert ANY DEFINED BY otherCertFormat }
 * </pre>
 * 
 * This implementation will only return the Certificate [Defined by 3280] but
 * for the purposes of this documentation it is an instance of a
 * java.security.X509Certificate
 * 
 * @see java.security.X509Certificate
 * @author tejohnson
 * @version $Revision: 3 $
 */
public class CertificateChoices {
	ASN1Object sc = new ASN1Object();

	/**
	 * Constructor for CertificateChoices.
	 * @param encoded ASN1Object
	 * @throws ASN1Exception
	 */
	public CertificateChoices(ASN1Object encoded) throws ASN1Exception {
		try {
			this.sc = new CON_SPEC(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
	}

	/**
	 * Constructor for CertificateChoices.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public CertificateChoices(byte[] encoded) throws ASN1Exception {
		try {
			this.sc = new ASN1Object(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
	}

	/**
	 * Method getCertificate.
	 * @return X509Certificate
	 * @throws ASN1Exception
	 */
	public X509Certificate getCertificate() throws ASN1Exception {
		// Render us a Certificate
		ByteArrayInputStream is = new ByteArrayInputStream(this.sc.getBytes());
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(is);
		} catch (CertificateException e) {
			throw new ASN1Exception(e);
		}
	}

}
