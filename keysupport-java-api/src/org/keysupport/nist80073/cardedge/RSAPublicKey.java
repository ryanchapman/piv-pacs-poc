/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: RSAPublicKey.java 13 2013-11-07 05:22:58Z grandamp@gmail.com $
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
 * @version $Revision: 13 $
 * Last changed: $LastChangedDate: 2013-11-06 22:22:58 -0700 (Wed, 06 Nov 2013) $
 *****************************************************************************/

package org.keysupport.nist80073.cardedge;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class RSAPublicKey extends AsymmetricPublicKey {

	// private final static boolean debug = true;

	private byte[] modulus;
	private byte[] publicExponent;

	private byte[] pubkey;

	/**
	 * Constructor for RSAPublicKey.
	 * @param ba byte[]
	 */
	public RSAPublicKey(byte[] ba) {
		decode(ba);
		this.pubkey = ba;
	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	public void decode(byte[] ba) {

		Enumeration<TLV> tlvs = BERTLVFactory.decodeTLV(ba);
		while (tlvs.hasMoreElements()) {
			TLV current_tlv = tlvs.nextElement();

			Enumeration<TLV> children = BERTLVFactory.decodeTLV(current_tlv
					.getValue());
			while (children.hasMoreElements()) {

				TLV child_tlv = children.nextElement();
				Tag child_tag = child_tlv.getTag();
				byte[] value = child_tlv.getValue();

				switch (child_tag.getBytes()[0]) {

				case Tag.PKDO_RSA_MODULUS: {
					this.modulus = value;
					break;
				}
				case Tag.PKDO_RSA_PUB_EXP: {
					this.publicExponent = value;
					break;
				}
				default: {
					break;
				}
				}
			}
		}

	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.pubkey;
	}

	/**
	 * Method getPublicKey.
	 * @return PublicKey
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public PublicKey getPublicKey() throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(1,
				this.modulus), new BigInteger(this.publicExponent));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pub = keyFactory.generatePublic(pubKeySpec);
		return pub;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Asymmetric Key:Modulus:\t"
				+ DataUtil.byteArrayToString(this.modulus));
		sb.append("\nAsymmetric Key:Public Exponent:\t"
				+ DataUtil.byteArrayToString(this.publicExponent));
		sb.append('\n');
		return sb.toString();
	}

}