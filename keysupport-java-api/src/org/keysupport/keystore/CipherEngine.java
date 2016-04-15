/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CipherEngine.java 15 2013-11-09 23:48:19Z grandamp@gmail.com $
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
 * @version $Revision: 15 $
 * Last changed: $LastChangedDate: 2013-11-09 16:48:19 -0700 (Sat, 09 Nov 2013) $
 *****************************************************************************/

package org.keysupport.keystore;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.keysupport.encoding.der.ObjectIdentifier;
import org.keysupport.util.DataUtil;

/**
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 15 $
 */
public class CipherEngine {

	private final static boolean debug = false;

	// 800-78 Table 6-1
	public final static byte PIV_AUTH_KEY = (byte) 0x9a;
	public final static byte CARD_MGMT_KEY = (byte) 0x9b;
	public final static byte DIG_SIG_KEY = (byte) 0x9c;
	public final static byte KEY_MGMT_KEY = (byte) 0x9d;
	public final static byte CARD_AUTH_KEY = (byte) 0x9e;

	// 800-78 Table 6-2
	public final static byte THREE_KEY_3DES_ECB = (byte) 0x00; // Also 0x03
	public final static byte TWO_KEY_3DES_ECB = (byte) 0x01;
	public final static byte RSA_1024 = (byte) 0x06;
	public final static byte RSA_2048 = (byte) 0x07;
	public final static byte AES_128_ECB = (byte) 0x08;
	public final static byte AES_192_ECB = (byte) 0x0A;
	public final static byte AES_256_ECB = (byte) 0x0C;
	public final static byte ECC_CURVE_P256 = (byte) 0x11;
	public final static byte ECC_CURVE_P384 = (byte) 0x14;

	// Algorithm OIDs from 800-78-3
	// Digests
	/**
	 * SHA-1 id-sha1 ::= {iso(1) identified-organization(3) oiw(14) secsig(3)
	 * algorithms(2) 26}
	 */
	public final static ObjectIdentifier SHA1 = new ObjectIdentifier(
			"1.3.14.3.2.26");

	/**
	 * SHA-256 id-sha256 ::= {joint-iso-itu-t(2) country(16) us(840)
	 * organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1}
	 */
	public final static ObjectIdentifier SHA256 = new ObjectIdentifier(
			"2.16.840.1.101.3.4.2.1");

	/**
	 * SHA-384 id-sha384 ::= {joint-iso-itu-t(2) country(16) us(840)
	 * organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 2}
	 */
	public final static ObjectIdentifier SHA384 = new ObjectIdentifier(
			"2.16.840.1.101.3.4.2.2");

	// Asymmetric Algorithms
	/**
	 * RSA id-rsa ::= {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	 * pkcs-1(1) 1}
	 */
	public final static ObjectIdentifier RSA = new ObjectIdentifier(
			"1.2.840.113549.1.1.1");

	/**
	 * ECDSA id-ecdsa::= {iso(1) member-body(2) us(840) ansi-X9-62(10045)
	 * id-publicKeyType(2) 1} --Technically ECDSA and ECDH Public Key
	 */
	public final static ObjectIdentifier ECDSA = new ObjectIdentifier(
			"1.2.840.10045.2.1");

	/**
	 * ECDH id-ecdh::= {iso(1) member-body(2) us(840) ansi-X9-62(10045)
	 * id-publicKeyType(2) 1} --Technically ECDSA and ECDH Public Key
	 */
	public final static ObjectIdentifier ECDH = new ObjectIdentifier(
			"1.2.840.10045.2.1");

	// Signature Algorithms
	/**
	 * RSA with SHA-1 and PKCS #1 v1.5 padding sha1WithRSAEncryption ::= {iso(1)
	 * member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 5}
	 */
	public final static ObjectIdentifier SHA1withRSA = new ObjectIdentifier(
			"1.2.840.113549.1.1.5");

	/**
	 * RSA with SHA-256 and PKCS #1 v1.5 padding sha256WithRSAEncryption ::=
	 * {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 11}
	 */
	public final static ObjectIdentifier SHA256withRSA = new ObjectIdentifier(
			"1.2.840.113549.1.1.11");

	/**
	 * RSA with SHA-256 and PSS padding id-RSASSA-PSS ::= {iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 10}
	 */
	public final static ObjectIdentifier SHA256withRSAPSS = new ObjectIdentifier(
			"1.2.840.113549.1.1.10");

	/**
	 * ECDSA with SHA-256 ecdsa-with-SHA256 ::= {iso(1) member-body(2) us(840)
	 * ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2 (3) 2}
	 */
	public final static ObjectIdentifier SHA256withECDSA = new ObjectIdentifier(
			"1.2.840.10045.4.3.2");

	/**
	 * ECDSA with SHA-384 ecdsa-with-SHA384 ::= {iso(1) member-body(2) us(840)
	 * ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2 (3) 3}
	 */
	public final static ObjectIdentifier SHA384withECDSA = new ObjectIdentifier(
			"1.2.840.10045.4.3.3");

	// Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE is used for calling opmode
	public final static int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
	public final static int DECRYPT_MODE = Cipher.DECRYPT_MODE;

	/**
	 * Method AES128CBC.
	 * 
	 * @param plaintext
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @param opmode
	 *            int
	 * @return byte[]
	 */
	public static byte[] AES128CBC(byte[] plaintext, byte[] key, int opmode) {

		byte[] ciphertext = null;

		try {

			IvParameterSpec iv = new IvParameterSpec(
					DataUtil.stringToByteArray("00000000000000000000000000000000"));
			SecretKeySpec ks = new SecretKeySpec(key, "AES");
			Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
			c.init(opmode, ks, iv);
			ciphertext = c.doFinal(plaintext);

		} catch (Throwable e) {
			e.printStackTrace();
		}

		return ciphertext;

	}

	/**
	 * Method getSigningAlgorithm.
	 * 
	 * @param sigalg
	 *            ObjectIdentifier
	 * @return String
	 * @throws NoSuchAlgorithmException
	 */
	public static String getSigningAlgorithm(ObjectIdentifier sigalg)
			throws NoSuchAlgorithmException {
        System.out.println("ENTER getSigningAlgorithm(sigalg): sigalg=");
        System.out.println(sigalg);
		if (sigalg.equals(SHA1withRSA)) {
			return "SHA1withRSA";
		} else if (sigalg.equals(SHA256withRSA)) {
			return "SHA256withRSA";
		} else if (sigalg.equals(SHA256withECDSA)) {
			return "SHA256withECDSA";
		} else if (sigalg.equals(SHA384withECDSA)) {
			return "SHA384withECDSA";
		} else {
			throw new NoSuchAlgorithmException(
					"Algorithm not included in NIST 800-78");
		}
	}

	/**
	 * 
	 * @param digest
	 *            ObjectIdentifier
	 * @param encryption
	 *            ObjectIdentifier
	 * @return String <digest>with<encryption>
	 */
	public static String getSigningAlgorithm(ObjectIdentifier digest,
			ObjectIdentifier encryption) {
		StringBuffer sb = new StringBuffer();

		if (digest.equals(SHA1)) {
			sb.append("SHA1");
		} else if (digest.equals(SHA256)) {
			sb.append("SHA256");
		} else if (digest.equals(SHA384)) {
			sb.append("SHA384");
		}

		sb.append("with");

		if (encryption.equals(RSA) 
				|| encryption.equals(SHA1withRSA)
				|| encryption.equals(SHA256withRSA)) {
			sb.append("RSA");
		} else if (encryption.equals(SHA256withRSAPSS)) {
			sb.append("RSAandMGF1");
		} else if (encryption.equals(ECDSA)
				|| encryption.equals(SHA256withECDSA)
				|| encryption.equals(SHA384withECDSA)) {
			sb.append("ECDSA");
		}
		if (debug) {
			System.out.println("Constructed SigAlg Name: " + sb.toString());
		}
		return sb.toString();
	}

	/**
	 * Method SCP0105SSKey.
	 * 
	 * @param CARD_CNG
	 *            byte[]
	 * @param HOST_CNG
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @return byte[]
	 */
	public static byte[] SCP0105SSKey(byte[] CARD_CNG, byte[] HOST_CNG,
			byte[] key) {

		// byte[] SKEY = null;

		byte[] HAC = { CARD_CNG[4], CARD_CNG[5], CARD_CNG[6], CARD_CNG[7],
				HOST_CNG[0], HOST_CNG[1], HOST_CNG[2], HOST_CNG[3],
				CARD_CNG[0], CARD_CNG[1], CARD_CNG[2], CARD_CNG[3],
				HOST_CNG[4], HOST_CNG[5], HOST_CNG[6], HOST_CNG[7] };

		if (debug) {
			System.out.println("Sess Diver Data: "
					+ DataUtil.byteArrayToString(HAC));
		}
		return TDES128ECB(HAC, key, ENCRYPT_MODE);

	}

	/**
	 * Method SCP03SSKey.
	 * 
	 * @param CARD_CNG
	 *            byte[]
	 * @param HOST_CNG
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @param keytype
	 *            int
	 * @return byte[]
	 */
	public static byte[] SCP03SSKey(byte[] CARD_CNG, byte[] HOST_CNG,
			byte[] key, int keytype) {

		int SCP03_S_ENC = 0;
		int SCP03_S_MAC = 1;

		byte[] S_ENC_CONSTANT = DataUtil
				.stringToByteArray("01820000000000000000000000000000");
		byte[] S_MAC_CONSTANT = DataUtil
				.stringToByteArray("01010000000000000000000000000000");

		byte[] SKEY = null;

		byte[] HAC = { CARD_CNG[0], CARD_CNG[1], CARD_CNG[2], CARD_CNG[3],
				CARD_CNG[4], CARD_CNG[5], CARD_CNG[6], CARD_CNG[7],
				HOST_CNG[0], HOST_CNG[1], HOST_CNG[2], HOST_CNG[3],
				HOST_CNG[4], HOST_CNG[5], HOST_CNG[6], HOST_CNG[7] };

		SKEY = AES128CBC(HAC, key, ENCRYPT_MODE);

		if (keytype == SCP03_S_ENC) {
			SKEY = DataUtil.XOR(SKEY, S_ENC_CONSTANT);
		} else if (keytype == SCP03_S_MAC) {
			SKEY = DataUtil.XOR(SKEY, S_MAC_CONSTANT);
		} else {
			// bad key type, throw exception
		}

		SKEY = AES128CBC(SKEY, key, ENCRYPT_MODE);

		return SKEY;
	}

	/**
	 * Method TDES128ECB.
	 * 
	 * @param plaintext
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @param opmode
	 *            int
	 * @return byte[]
	 */
	public static byte[] TDES128ECB(byte[] plaintext, byte[] key, int opmode) {

		byte[] ciphertext = null;

		try {
			// 2KTDEA key is encountered, expand to 192 bit
			if (key.length == 16) {
				if (debug) {
					System.out.println("Expanding from 128 to 192");
				}
				byte[] ekey = new byte[24];
				System.arraycopy(key, 0, ekey, 0, key.length);
				System.arraycopy(key, 0, ekey, key.length, key.length / 2);
			}

			ciphertext = TDESECB(plaintext, key, opmode);

		} catch (Throwable e) {
			e.printStackTrace();
		}

		return ciphertext;

	}

	/**
	 * Method TDES198ECB.
	 * 
	 * @param plaintext
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @param opmode
	 *            int
	 * @return byte[]
	 */
	public static byte[] TDES198ECB(byte[] plaintext, SecretKey key, int opmode) {

		byte[] ciphertext = null;

		try {

			// DESedeKeySpec ks = new DESedeKeySpec(key);
			// SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
			// SecretKey sk = kf.generateSecret(ks);
			Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
			c.init(opmode, key);
			ciphertext = c.doFinal(plaintext);

		} catch (Throwable e) {
			e.printStackTrace();
		}

		return ciphertext;
	}

	/**
	 * Method TDESCBC.
	 * 
	 * @param plaintext
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @param iv
	 *            byte[]
	 * @param opmode
	 *            int
	 * @return byte[]
	 */
	public static byte[] TDESCBC(byte[] plaintext, byte[] key, byte[] iv,
			int opmode) {

		byte[] ciphertext = null;

		try {
			// 2KTDEA key is encountered, expand to 192 bit
			byte[] _key;
			if (key.length == 16) {
				if (debug) {
					System.out.println("Expanding from 128 to 192");
				}
				byte[] ekey = new byte[24];
				System.arraycopy(key, 0, ekey, 0, key.length);
				System.arraycopy(key, 0, ekey, key.length, key.length / 2);
				_key = ekey;
			} else {
				_key = key;
			}

			if (debug) {
				System.out.println("Key: " + DataUtil.byteArrayToString(_key));
			}
			IvParameterSpec ivv = new IvParameterSpec(iv);
			DESedeKeySpec ks = new DESedeKeySpec(_key);
			SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
			SecretKey sk = kf.generateSecret(ks);
			Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
			c.init(opmode, sk, ivv);
			ciphertext = c.doFinal(plaintext);

		} catch (Throwable e) {
			e.printStackTrace();
		}

		return ciphertext;
	}

	/**
	 * Method TDESECB.
	 * 
	 * @param plaintext
	 *            byte[]
	 * @param key
	 *            byte[]
	 * @param opmode
	 *            int
	 * @return byte[]
	 */
	public static byte[] TDESECB(byte[] plaintext, byte[] key, int opmode) {

		byte[] ciphertext = null;

		try {
			// 2KTDEA key is encountered, expand to 192 bit
			byte[] _key;
			if (key.length == 16) {
				if (debug) {
					System.out.println("Expanding from 128 to 192");
				}
				byte[] ekey = new byte[24];
				System.arraycopy(key, 0, ekey, 0, key.length);
				System.arraycopy(key, 0, ekey, key.length, key.length / 2);
				_key = ekey;
			} else {
				_key = key;
			}

			if (debug) {
				System.out.println("Key: " + DataUtil.byteArrayToString(_key));
			}
			DESedeKeySpec ks = new DESedeKeySpec(_key);
			SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
			SecretKey sk = kf.generateSecret(ks);
			Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
			c.init(opmode, sk);
			ciphertext = c.doFinal(plaintext);

		} catch (Throwable e) {
			e.printStackTrace();
		}

		return ciphertext;
	}
}
