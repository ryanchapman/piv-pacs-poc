/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: ECPublicKey.java 13 2013-11-07 05:22:58Z grandamp@gmail.com $
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 13 $
 */
public class ECPublicKey extends AsymmetricPublicKey {

	// private final static boolean debug = true;

	/**
	 * Field P256_POINT_SIZE. (value is 65)
	 */
	private final static int P256_POINT_SIZE = 65;
	/**
	 * Field P384_POINT_SIZE. (value is 97)
	 */
	private final static int P384_POINT_SIZE = 97;

	/**
	 * Field point.
	 */
	private byte[] point;
	/**
	 * Field pubkey.
	 */
	private byte[] pubkey;
	/**
	 * Field x.
	 */
	private byte[] x = null;
	/**
	 * Field y.
	 */
	private byte[] y = null;
	/**
	 * Field size.
	 */
	private int size = 0;

	/**
	 * Constructor for RSAPublicKey.
	 * 
	 * @param ba
	 *            byte[]
	 */
	public ECPublicKey(byte[] ba) {
		decode(ba);
		this.pubkey = ba;
	}

	/**
	 * Method decode.
	 * 
	 * @param ba
	 *            byte[]
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

				case Tag.PKDO_ECDSA_POINT: {
					this.point = value;
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
	 * 
	 * 
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.pubkey;
	}

	/**
	 * Method getPublicKey.
	 * 
	 * 
	 * 
	 * 
	 * 
	 * @return PublicKey * @throws NoSuchAlgorithmException * @throws
	 *         InvalidKeySpecException * @throws IOException
	 */
	public PublicKey getPublicKey() throws NoSuchAlgorithmException,
			InvalidKeySpecException, IOException {

		ECParameterSpec ecps = null;
		/*
		 * Check the obtained point and ensure it is what we expect
		 */
		if (this.point == null || this.point.length == 0) {
			throw new IOException("Point is zero length or null");
		}
		if (this.point[0] != 4) {
			throw new IOException("Only uncompressed point format supported");
		}
		/*
		 * determine key size and get the correct keyspec
		 */
		if (this.point.length == P256_POINT_SIZE) {
			ecps = getP256PSpec();
			this.size = (((this.point.length - 1) / 2) / Byte.SIZE);
		} else if (this.point.length == P384_POINT_SIZE) {
			ecps = getP384PSpec();
			this.size = (((this.point.length - 1) / 2) / Byte.SIZE);
		} else {
			throw new InvalidKeySpecException(
					"Curve is not one of the NIST defined curves for FIPS-201");
		}
		/*
		 * Parse x and y points from w into BigInteger objects and render the
		 * point
		 */
		this.x = new byte[this.size];
		this.y = new byte[this.size];
		System.arraycopy(this.point, 1, this.x, 0, this.size);
		System.arraycopy(this.point, this.size + 1, this.y, 0, this.size);
		ECPoint ecp = new ECPoint(new BigInteger(1, this.x), new BigInteger(1,
				this.y));

		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecp, ecps);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey pub = keyFactory.generatePublic(pubKeySpec);
		return pub;
	}

	/*
	 * Curve parameters via the Sun/Oracle Named Curve implementation. The curve
	 * parameter establishment is defined here in order to improve performance
	 * since we only recognize 2 named curves.
	 * 
	 * Curve parameters are defined in: STANDARDS FOR EFFICIENT CRYPTOGRAPHY SEC
	 * 2: Recommended Elliptic Curve Domain Parameters
	 * http://www.secg.org/collateral/sec2_final.pdf
	 * 
	 * For P-256: 2.7.2 Recommended Parameters secp256r1 For P-384: 2.8.1
	 * Recommended Parameters secp384r1
	 * 
	 * Encoding of point from the card defined in:
	 * http://www.secg.org/collateral/sec1_final.pdf
	 */

	/**
	 * Method getP256PSpec.
	 * 
	 * @return ECParameterSpec
	 */
	public ECParameterSpec getP256PSpec() {
		byte[] pBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		byte[] aBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC };
		byte[] bBytes = new byte[] { (byte) 0x5A, (byte) 0xC6, (byte) 0x35,
				(byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93,
				(byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD,
				(byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86,
				(byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06,
				(byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0,
				(byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C,
				(byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B };
		byte[] xBytes = new byte[] { (byte) 0x6B, (byte) 0x17, (byte) 0xD1,
				(byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42,
				(byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6,
				(byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40,
				(byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D,
				(byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33,
				(byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39,
				(byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96 };
		byte[] yBytes = new byte[] { (byte) 0x4F, (byte) 0xE3, (byte) 0x42,
				(byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
				(byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB,
				(byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E,
				(byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33,
				(byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E,
				(byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40,
				(byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5 };
		byte[] nBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA,
				(byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E,
				(byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA,
				(byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51 };
		ECParameterSpec p256 = null;
		ECField field = new ECFieldFp(new BigInteger(1, pBytes));
		EllipticCurve curve = new EllipticCurve(field,
				new BigInteger(1, aBytes), new BigInteger(1, bBytes));
		ECPoint g = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1,
				yBytes));
		p256 = new ECParameterSpec(curve, g, new BigInteger(1, nBytes), 1);
		return p256;
	}

	/**
	 * Method getP384PSpec.
	 * 
	 * @return ECParameterSpec
	 */
	public ECParameterSpec getP384PSpec() {
		byte[] pBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		byte[] aBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC };
		byte[] bBytes = new byte[] { (byte) 0xB3, (byte) 0x31, (byte) 0x2F,
				(byte) 0xA7, (byte) 0xE2, (byte) 0x3E, (byte) 0xE7,
				(byte) 0xE4, (byte) 0x98, (byte) 0x8E, (byte) 0x05,
				(byte) 0x6B, (byte) 0xE3, (byte) 0xF8, (byte) 0x2D,
				(byte) 0x19, (byte) 0x18, (byte) 0x1D, (byte) 0x9C,
				(byte) 0x6E, (byte) 0xFE, (byte) 0x81, (byte) 0x41,
				(byte) 0x12, (byte) 0x03, (byte) 0x14, (byte) 0x08,
				(byte) 0x8F, (byte) 0x50, (byte) 0x13, (byte) 0x87,
				(byte) 0x5A, (byte) 0xC6, (byte) 0x56, (byte) 0x39,
				(byte) 0x8D, (byte) 0x8A, (byte) 0x2E, (byte) 0xD1,
				(byte) 0x9D, (byte) 0x2A, (byte) 0x85, (byte) 0xC8,
				(byte) 0xED, (byte) 0xD3, (byte) 0xEC, (byte) 0x2A, (byte) 0xEF };
		byte[] xBytes = new byte[] { (byte) 0xAA, (byte) 0x87, (byte) 0xCA,
				(byte) 0x22, (byte) 0xBE, (byte) 0x8B, (byte) 0x05,
				(byte) 0x37, (byte) 0x8E, (byte) 0xB1, (byte) 0xC7,
				(byte) 0x1E, (byte) 0xF3, (byte) 0x20, (byte) 0xAD,
				(byte) 0x74, (byte) 0x6E, (byte) 0x1D, (byte) 0x3B,
				(byte) 0x62, (byte) 0x8B, (byte) 0xA7, (byte) 0x9B,
				(byte) 0x98, (byte) 0x59, (byte) 0xF7, (byte) 0x41,
				(byte) 0xE0, (byte) 0x82, (byte) 0x54, (byte) 0x2A,
				(byte) 0x38, (byte) 0x55, (byte) 0x02, (byte) 0xF2,
				(byte) 0x5D, (byte) 0xBF, (byte) 0x55, (byte) 0x29,
				(byte) 0x6C, (byte) 0x3A, (byte) 0x54, (byte) 0x5E,
				(byte) 0x38, (byte) 0x72, (byte) 0x76, (byte) 0x0A, (byte) 0xB7 };
		byte[] yBytes = new byte[] { (byte) 0x36, (byte) 0x17, (byte) 0xDE,
				(byte) 0x4A, (byte) 0x96, (byte) 0x26, (byte) 0x2C,
				(byte) 0x6F, (byte) 0x5D, (byte) 0x9E, (byte) 0x98,
				(byte) 0xBF, (byte) 0x92, (byte) 0x92, (byte) 0xDC,
				(byte) 0x29, (byte) 0xF8, (byte) 0xF4, (byte) 0x1D,
				(byte) 0xBD, (byte) 0x28, (byte) 0x9A, (byte) 0x14,
				(byte) 0x7C, (byte) 0xE9, (byte) 0xDA, (byte) 0x31,
				(byte) 0x13, (byte) 0xB5, (byte) 0xF0, (byte) 0xB8,
				(byte) 0xC0, (byte) 0x0A, (byte) 0x60, (byte) 0xB1,
				(byte) 0xCE, (byte) 0x1D, (byte) 0x7E, (byte) 0x81,
				(byte) 0x9D, (byte) 0x7A, (byte) 0x43, (byte) 0x1D,
				(byte) 0x7C, (byte) 0x90, (byte) 0xEA, (byte) 0x0E, (byte) 0x5F };
		byte[] nBytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xC7, (byte) 0x63, (byte) 0x4D,
				(byte) 0x81, (byte) 0xF4, (byte) 0x37, (byte) 0x2D,
				(byte) 0xDF, (byte) 0x58, (byte) 0x1A, (byte) 0x0D,
				(byte) 0xB2, (byte) 0x48, (byte) 0xB0, (byte) 0xA7,
				(byte) 0x7A, (byte) 0xEC, (byte) 0xEC, (byte) 0x19,
				(byte) 0x6A, (byte) 0xCC, (byte) 0xC5, (byte) 0x29, (byte) 0x73 };
		ECParameterSpec p384 = null;
		ECField field = new ECFieldFp(new BigInteger(1, pBytes));
		EllipticCurve curve = new EllipticCurve(field,
				new BigInteger(1, aBytes), new BigInteger(1, bBytes));
		ECPoint g = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1,
				yBytes));
		p384 = new ECParameterSpec(curve, g, new BigInteger(1, nBytes), 1);
		return p384;
	}

	/**
	 * Method toString.
	 * 
	 * 
	 * @return String
	 */
	@Override
	public String toString() {
		String sizeStr = null;
		if (this.size == (((P256_POINT_SIZE - 1) / 2) / Byte.SIZE)) {
			sizeStr = "P-256 (secp256r1) [1.2.840.10045.3.1.7]";
		} else {
			sizeStr = "P-384 (secp384r1) [1.3.132.0.34]";
		}
		StringBuffer sb = new StringBuffer();
		sb.append("Asymmetric Key:Curve:\t" + sizeStr);
		sb.append("\nAsymmetric Key:Point X Coordinate:\t"
				+ DataUtil.byteArrayToString(this.x));
		sb.append("\nAsymmetric Key:Point Y Coordinate:\t"
				+ DataUtil.byteArrayToString(this.y));
		sb.append('\n');
		return sb.toString();
	}

}