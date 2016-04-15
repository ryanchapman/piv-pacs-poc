/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: DigestInfo.java 16 2013-11-11 22:12:44Z grandamp@gmail.com $
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
 * @version $Revision: 16 $
 * Last changed: $LastChangedDate: 2013-11-11 15:12:44 -0700 (Mon, 11 Nov 2013) $
 *****************************************************************************/

package org.keysupport.encoding.der.structures;

import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3447.txt">RFC3447</A>
 * 
 * <pre>
 *  DigestInfo  ::=  SEQUENCE  {
 *       digestAlgorithm         AlgorithmIdentifier,
 *       digest                  OCTET STRING  }
 * </pre>
 * 
 * @author tejohnson
 * @version $Revision: 16 $
 */
public class DigestInfo {

	private SEQUENCE di = new SEQUENCE();
	private ASN1Object dalg = new ASN1Object();
	private ASN1Object digest = new ASN1Object();

	/**
	 * Constructor for DigestInfo.
	 * 
	 * @param encoded
	 *            ASN1Object
	 * @throws ASN1Exception
	 */
	public DigestInfo(ASN1Object encoded) throws ASN1Exception {
		this.di = new SEQUENCE(encoded);
		this.decode();
	}

	/**
	 * Constructor for DigestInfo.
	 * 
	 * @param encoded
	 *            byte[]
	 * @throws ASN1Exception
	 */
	public DigestInfo(byte[] encoded) throws ASN1Exception {
		try {
			this.di = new SEQUENCE(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.decode();
	}

	/**
	 * Constructor for DigestInfo.
	 * 
	 * @param dalg
	 *            AlgorithmIdentifier
	 * @param digest
	 *            byte[]
	 * @throws ASN1Exception
	 */
	public DigestInfo(AlgorithmIdentifier dalg, byte[] digest)
			throws ASN1Exception {
		this.dalg = dalg.getASN1Object();
		this.di.addComponent(this.dalg);
		this.digest = ASN1Factory.encodeASN1Object(new Tag(Tag.OCTETSTRING),
				digest);
		this.di.addComponent(this.digest);
	}

	/**
	 * Method decode.
	 * 
	 * @throws ASN1Exception
	 */
	private void decode() throws ASN1Exception {
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.di.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.dalg = en.nextElement();
		}
		if (en.hasMoreElements()) {
			this.digest = en.nextElement();
		}
	}

	/**
	 * Method getAlgID.
	 * 
	 * @return AlgorithmIdentifier
	 * @throws ASN1Exception 
	 */
	public AlgorithmIdentifier getAlgID() throws ASN1Exception {
		return new AlgorithmIdentifier(this.dalg);
	}

	/**
	 * Method getAlgOID.
	 * 
	 * @return byte[]
	 */
	public byte[] getDigest() {
		return this.digest.getValue();
	}

	/**
	 * Method getBytes.
	 * 
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.di.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * 
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.di;
	}

	/**
	 * Method toString.
	 * 
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("SEQUENCE {\n");
		sb.append("\t [AlgorithmIdentifier],\n");
			sb.append("\t" + DataUtil.byteArrayToString(this.digest.getValue())
					+ "\n");
		sb.append("}\n");
		return sb.toString();
	}

}
