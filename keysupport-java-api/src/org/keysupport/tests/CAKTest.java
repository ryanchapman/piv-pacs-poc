/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CAKTest.java 25 2014-07-08 17:02:30Z grandamp@gmail.com $
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
 * @version $Revision: 25 $
 * Last changed: $LastChangedDate: 2014-07-08 11:02:30 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.tests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.List;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.der.structures.AlgorithmIdentifier;
import org.keysupport.encoding.der.structures.DigestInfo;
import org.keysupport.keystore.CipherEngine;
import org.keysupport.keystore.DigestEngine;
import org.keysupport.keystore.PaddingEngine;
import org.keysupport.nist80073.PIVCard;
import org.keysupport.nist80073.cardedge.DynamicAuthTempl;
import org.keysupport.nist80073.cardedge.PIVAPDU;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.util.DataUtil;

public class CAKTest {

	private final static boolean debug = true;
	private static PIVCard card = null;

	/*****************************************************************************
	 * Still cleaning up this code...
	 * 
	 * Reference: NIST SP 800-73-3, Part(s) 1 & 2
	 * 
	 * Full debugging: java -Xmx512m -Djava.security.debug=all CAKTest 
	 * 
	 * The -Xmx512m is necessary when performing full validation, where the
	 * memory is so high to support PDVal testing if the cert path is verified.
	 * 
	 * @author Todd E. Johnson tejohnson@yahoo.com
	 ****************************************************************************/

	public static void main(String args[]) {
		try {

			byte[] nonce = null;

			/*
			 * Generate our data to have signed
			 */
			nonce = getNonce(256);


			/*
			 * Sign the nonce
			 */
			getCard();
			CardChannel channel = card.getChannel();
			performPOP(channel, nonce);

			/*
			 * Verify the Signature
			 */

			/*
			 * Disconnect
			 */
			card.disconnect(false);

		} catch (CardException e) {
			e.printStackTrace();
		}
	}

	public static void performPOP(CardChannel channel,
			byte[] nonce) {
		ResponseAPDU response = null;
		/*
		 * Perform a POP test using cardAuth key and use the associated
		 * certificate for validation
		 */
		PIVCertificate cardAuthPC = null;
		byte[] rbDigest = null;


		try {
			try {
				cardAuthPC = card.getCardAuthCert();
			} catch (NullPointerException e) {
				cardAuthPC = null;
			}

			if (cardAuthPC != null) {

				X509Certificate cardAuth = cardAuthPC.getCertificate();
				String keyAlgo = cardAuth.getPublicKey().getAlgorithm();
				System.out.println("Card Authentication Certificate Key Type: "
						+ keyAlgo);

				/*
				 * Determine RSA or ECC
				 */
				if (keyAlgo.equalsIgnoreCase("RSA")) {

					RSAPublicKey pub = (RSAPublicKey) cardAuth.getPublicKey();

					byte pivkeytype = 0;

					int modsize = pub.getModulus().toByteArray().length;
					if (modsize >= 128 && modsize <= 256) {
						modsize = 128;
						pivkeytype = CipherEngine.RSA_1024;
					}
					if (modsize >= 256 && modsize <= 384) {
						modsize = 256;
						pivkeytype = CipherEngine.RSA_2048;
					}

					/*
					 * Digest the data to be signed
					 */
					rbDigest = DigestEngine.sHA256Sum(nonce);
					System.out.println("SHA-256 Digest of our " + nonce.length
							+ " byte random:\n" + DataUtil.byteArrayToString(rbDigest));

					
					System.out.println("RSA Mod is " + modsize + " bytes.");

					AlgorithmIdentifier ai = new AlgorithmIdentifier(
							CipherEngine.SHA256, null);
					DigestInfo di = new DigestInfo(ai, rbDigest);
					byte[] diBytes = di.getBytes();
					byte[] message = PaddingEngine.pkcs1v1_5Pad(diBytes,
							modsize);

					DynamicAuthTempl gaReq = new DynamicAuthTempl(
							DynamicAuthTempl.POP_TO_TERM_RSA, message);

					Enumeration<CommandAPDU> gaapdus = PIVAPDU
							.generalAuthenticate(pivkeytype,
									CipherEngine.CARD_AUTH_KEY,
									gaReq.getEncoded());
					CommandAPDU gaapdu;
					while (gaapdus.hasMoreElements()) {
						gaapdu = gaapdus.nextElement();
						if (debug) {
							System.out
									.println("PUT APDU: " + gaapdu.toString());
							System.out.println("PUT APDU: "
									+ DataUtil.byteArrayToString(gaapdu
											.getBytes()));
						}
						response = channel.transmit(gaapdu);
						if (debug) {
							// Show response from last command APDU
							System.out.println(response.toString()
									+ ":\n"
									+ DataUtil.byteArrayToString(response
											.getData()));
						}
					}

					DynamicAuthTempl gaResp = new DynamicAuthTempl(
							response.getData());
					if (debug) {
						System.out.println(gaResp.toString());
					}
					/*
					 * Test the signature
					 */
					byte[] signature = gaResp.getTemplateValue();
					boolean verified = verifySignature("SHA256withRSA",
							cardAuth, signature, nonce);
					/*
					 * PASS/FAIL
					 */
					if (verified) {
						System.out.println("Signature Valid, POP Successful.");
					} else {
						System.out.println("Signature NOT Valid, POP Failed!");
					}
				} else {
					ECPublicKey pub = (ECPublicKey) cardAuth.getPublicKey();

					byte pivkeytype = 0;
					int wSize = pub.getW().getAffineX().toByteArray().length;
					if (wSize >= 32 && wSize <= 48) {
						wSize = 32;
						pivkeytype = CipherEngine.ECC_CURVE_P256;
						/*
						 * Digest the data to be signed
						 */
						rbDigest = DigestEngine.sHA256Sum(nonce);
						System.out.println("SHA-256 Digest of our " + nonce.length
								+ " byte random:\n" + DataUtil.byteArrayToString(rbDigest));
					}
					if (wSize >= 48 && wSize <= 64) {
						wSize = 48;
						pivkeytype = CipherEngine.ECC_CURVE_P384;
						/*
						 * Digest the data to be signed
						 */
						rbDigest = DigestEngine.sHA384Sum(nonce);
						System.out.println("SHA-384 Digest of our " + nonce.length
								+ " byte random:\n" + DataUtil.byteArrayToString(rbDigest));
					}
					System.out.println("Key Size: " + wSize);

					DynamicAuthTempl gaReq = new DynamicAuthTempl(
							DynamicAuthTempl.POP_TO_TERM_ECC, rbDigest);

					Enumeration<CommandAPDU> gaapdus = PIVAPDU
							.generalAuthenticate(pivkeytype,
									CipherEngine.CARD_AUTH_KEY,
									gaReq.getEncoded());
					CommandAPDU gaapdu;
					while (gaapdus.hasMoreElements()) {
						gaapdu = gaapdus.nextElement();
						if (debug) {
							System.out
									.println("PUT APDU: " + gaapdu.toString());
							System.out.println("PUT APDU: "
									+ DataUtil.byteArrayToString(gaapdu
											.getBytes()));
						}
						response = channel.transmit(gaapdu);
						if (debug) {
							// Show response from last command APDU
							System.out.println(response.toString()
									+ ":\n"
									+ DataUtil.byteArrayToString(response
											.getData()));
						}
					}

					DynamicAuthTempl gaResp = new DynamicAuthTempl(
							response.getData());
					if (debug) {
						System.out.println(gaResp.toString());
					}
					/*
					 * Test the signature
					 */
					byte[] signature = gaResp.getTemplateValue();
					boolean verified = verifySignature("SHA256withECDSA",
							cardAuth, signature, nonce);
					/*
					 * PASS/FAIL
					 */
					if (verified) {
						System.out.println("Signature Valid, POP Successful.");
					} else {
						System.out.println("Signature NOT Valid, POP Failed!");
					}
				}
			} else {
				System.out.println("NO CAK!");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CardException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (ASN1Exception e) {
			e.printStackTrace();
		}

	}

	public static boolean verifySignature(String sigAlg, X509Certificate cert,
			byte[] signedData, byte[] origData) {

		boolean verified = false;
		Signature sig = null;

		try {
			System.out.println("Sig Bytes: "
					+ DataUtil.byteArrayToString(signedData));
			System.out.println("Msg Bytes: "
					+ DataUtil.byteArrayToString(origData));
			System.out.println("Public Key: "
					+ DataUtil.byteArrayToString(cert.getPublicKey().getEncoded()));
			
			sig = Signature.getInstance(sigAlg);
			sig.initVerify(cert.getPublicKey());
			
			sig.update(origData);
			verified = sig.verify(signedData);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Bad Signing Algorithm: "
					+ e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Invalid Key: " + e.getLocalizedMessage());
		} catch (SignatureException e) {
			System.out.println("Bad Signature: " + e.getLocalizedMessage());
		}
		return verified;
	}

	public static byte[] getNonce(int size) {
		SecureRandom random = null;
		byte[] nonce = null;

		nonce = new byte[256];
		random = new SecureRandom();
		random.nextBytes(nonce);

		System.out.println("Our " + nonce.length + " byte random:\n"
				+ DataUtil.byteArrayToString(nonce));
		return nonce;
	}

	public static void getCard() {

		TerminalFactory factory = null;
		List<?> terminals = null;
		BufferedReader input = null;
		CardTerminal terminal = null;

		try {

			System.out.println("- KeySupport PIV API Test-\n");

			/*
			 * Show the list of available terminals
			 */
			factory = TerminalFactory.getDefault();
			System.out.println("Provider: " + factory.getProvider().getName()
					+ " - " + factory.getProvider().getInfo());
			terminals = factory.terminals().list();
			System.out.println("Available Card Readers:\n");
			for (int i = 0; i < terminals.size(); i++) {
				CardTerminal term = (CardTerminal) terminals.get(i);
				int dnum = i + 1;
				System.out.println(dnum + ": " + term.getName());
			}
			System.out
					.println("\nEnter a number of the reader which contains the PIV credential,");
			System.out.println("and then press [Enter]:");
			input = new BufferedReader(new InputStreamReader(System.in));
			int reader_num = 1;
			reader_num = Integer.parseInt(input.readLine());

			/*
			 * Get the identified terminal
			 */
			terminal = (CardTerminal) terminals.get(reader_num - 1);

			if (!terminal.isCardPresent()) {
				System.out
						.println("Please insert or hover the card over the reader.");
				terminal.waitForCardPresent(0);
			}

			/*
			 * Establish a connection with the card
			 */
			card = new PIVCard(terminal.connect("*"));

			/*
			 * Print the Card ATR
			 */
			System.out.println("Card: " + card);
			System.out.println("Card ATR: "
					+ DataUtil.byteArrayToString(card.getATR().getBytes()));

		} catch (NumberFormatException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CardException e) {
			e.printStackTrace();
		} catch (TLVEncodingException e) {
			e.printStackTrace();
		}
	}
}
