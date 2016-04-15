/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: AlgorithmIdentifier.java 14 2013-11-09 23:16:44Z grandamp@gmail.com $
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
 * @version $Revision: 14 $
 * Last changed: $LastChangedDate: 2013-11-09 16:16:44 -0700 (Sat, 09 Nov 2013) $
 *****************************************************************************/

package org.keysupport.encoding.der.structures;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.NULL;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;
import org.keysupport.encoding.der.ObjectIdentifier;
import org.keysupport.util.DataUtil;

/**
 * Per: <A HREF="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</A>
 * 
 * <pre>
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 * </pre>
 * 
 * @author tejohnson
 * @version $Revision: 14 $
 */
public class AlgorithmIdentifier {

	private SEQUENCE ai = new SEQUENCE();
	private ASN1Object ident = new ASN1Object();
	private ASN1Object param = new ASN1Object();

	/**
	 * Constructor for AlgorithmIdentifier.
	 * 
	 * @param encoded
	 *            ASN1Object
	 * @throws ASN1Exception
	 */
	public AlgorithmIdentifier(ASN1Object encoded) throws ASN1Exception {
		this.ai = new SEQUENCE(encoded);
		this.decode();
	}

	/**
	 * Constructor for AlgorithmIdentifier.
	 * 
	 * @param encoded
	 *            byte[]
	 * @throws ASN1Exception
	 */
	public AlgorithmIdentifier(byte[] encoded) throws ASN1Exception {
		try {
			this.ai = new SEQUENCE(encoded);
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		this.decode();
	}

	/**
	 * Constructor for AlgorithmIdentifier.
	 * 
	 * @param oid
	 *            ObjectIdentifier
	 * @param param
	 *            AlgorithmParameters
	 * @throws ASN1Exception
	 */
	public AlgorithmIdentifier(ObjectIdentifier oid, AlgorithmParameters param)
			throws ASN1Exception {
		this.ident = ASN1Factory.encodeASN1Object(new Tag(Tag.OBJECTID),
				oid.getEncoded());
		this.ai.addComponent(this.ident);
		if (param == null) {
			try {
				this.param = new NULL();
			} catch (TLVEncodingException e) {
				throw new ASN1Exception(e);
			}
			this.ai.addComponent(this.param);
		}
	}

	/**
	 * Method decode.
	 * 
	 * @throws ASN1Exception
	 */
	private void decode() throws ASN1Exception {
		Enumeration<ASN1Object> en = null;
		try {
			en = ASN1Factory.decodeASN1Object(this.ai.getValue());
		} catch (TLVEncodingException e) {
			throw new ASN1Exception(e);
		}
		if (en.hasMoreElements()) {
			this.ident = en.nextElement();
		}
		if (en.hasMoreElements()) {
			this.param = en.nextElement();
		}
	}

	/**
	 * Method getAlgParam.
	 * 
	 * @return AlgorithmParameters
	 * @param jceName
	 *            The name of the algorithm parameters which may depend on the
	 *            provider
	 */
	public AlgorithmParameters getAlgParam(String jceName)
			throws NoSuchAlgorithmException, IOException {
		if (this.param == null) {
			return null;
		}
		AlgorithmParameters ap = AlgorithmParameters.getInstance(jceName);
		ap.init(this.param.getValue());
		return ap;
	}

	/**
	 * Method getAlgOID.
	 * 
	 * @return ObjectIdentifier
	 */
	public ObjectIdentifier getAlgOID() {
		return new ObjectIdentifier(this.ident.getValue());
	}

	/**
	 * Method getBytes.
	 * 
	 * @return byte[]
	 */
	public byte[] getBytes() {
		return this.ai.getBytes();
	}

	/**
	 * Method getASN1Object.
	 * 
	 * @return ASN1Object
	 */
	public ASN1Object getASN1Object() {
		return this.ai;
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
		sb.append("\t" + this.getAlgOID().toString() + ",\n");
		if (this.param.isA(NULL.NULL)) {
			sb.append("\tNULL\n");
		} else {
			sb.append("\t" + DataUtil.byteArrayToString(this.param.getBytes())
					+ "\n");
		}
		sb.append("}\n");
		return sb.toString();
	}

}
