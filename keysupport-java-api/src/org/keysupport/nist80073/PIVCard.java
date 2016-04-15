/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCard.java 32 2014-07-08 17:06:24Z grandamp@gmail.com $
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
 * @version $Revision: 32 $
 * Last changed: $LastChangedDate: 2014-07-08 11:06:24 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.nist80073;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.keysupport.encoding.TLV;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;
import org.keysupport.keystore.CipherEngine;
import org.keysupport.keystore.KeyStoreManager;
import org.keysupport.nist80073.cardedge.DynamicAuthTempl;
import org.keysupport.nist80073.cardedge.PIVAPDU;
import org.keysupport.nist80073.cardedge.PIVAPDUInterface;
import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.PIVCardApplicationProperty;
import org.keysupport.nist80073.datamodel.PIVCardCapabilityContainer;
import org.keysupport.nist80073.datamodel.PIVCardHolderFacialImage;
import org.keysupport.nist80073.datamodel.PIVCardHolderFingerprints;
import org.keysupport.nist80073.datamodel.PIVCardHolderIrisImages;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.nist80073.datamodel.PIVDiscoveryObject;
import org.keysupport.nist80073.datamodel.PIVKeyHistoryObject;
import org.keysupport.nist80073.datamodel.PIVPrintedInformation;
import org.keysupport.nist80073.datamodel.PIVSecurityObject;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVCard {

	/**
	 */
	private static enum Auth {
		NONE, USER, ADMIN
	}

	private final static boolean debug = true;

	// state of this card connection
	private volatile Auth auth;

	private Card card;
	private PIVCardApplicationProperty pcap;
	private PIVDiscoveryObject pdo;
	private boolean hasDiscoveryObject = false;
	private CardChannel channel;

	/**
	 * Constructor for PIVCard.
	 * @param card Card
	 * @throws CardException
	 * @throws IOException
	 * @throws TLVEncodingException
	 */
	public PIVCard(Card card) throws CardException, IOException, TLVEncodingException {
		this.card = card;
		this.channel = card.getBasicChannel();

		ResponseAPDU response;

		// Select the PIV application
		CommandAPDU command = PIVAPDU.selectPIVApplication();
		if (debug) {
			System.out.println(command.toString() + ": "
					+ DataUtil.byteArrayToString(command.getBytes()));
		}

		/*
		 * Get the PCAP. Response may vary depending on the card, 
		 * so deal with it.  In reality, the PCAP should be small
		 * enough to fit in a single APDU, but we will prepare to
		 * receive the PCAP in chained response APDUs in the event of 
		 * future expansion in size.
		 * 
		 * The PCAP on some cards may be returned as defined in 800-73,
		 * where the PCAP is 61[size][value]9000, meaning it is delivered
		 * in the application property template with a 7816 response of
		 * 9000 indicating NO ERROR, or Successful Execution.
		 * 
		 * Otherwise, the PCAP may not be immediately returned, but a
		 * 7816 response of 61xx is given indicating BYTES REMAINING, where
		 * xx is the number of bytes remaining.  If xx = 00, then there are
		 * more than 255 bytes remaining.  The PCAP data can be retrieved
		 * by performing GET DATA commands until there are no bytes remaining
		 * and 9000 is received.
		 * 
		 * Regardless, an application property is to be returned upon
		 * selecting the PIV AID.
		 */
		response = this.channel.transmit(command);
		int status_word = response.getSW();
		int SW1 = response.getSW1();
		int SW2 = response.getSW2();

		if (SW1 == 0x61) {
			ByteArrayOutputStream rbaos = new ByteArrayOutputStream();
			if (debug) {
				System.out.println(response.toString() + ": "
						+ DataUtil.byteArrayToString(response.getData()));
			}
			rbaos.write(response.getData());
			while (SW1 == 0x61) {
				// Craft a GET-DATA APDU to collect the bytes remaining
				if (SW2 == 0x00) {
					CommandAPDU remain = new CommandAPDU(
							DataUtil.stringToByteArray("00C0000000"));
					if (debug) {
						System.out.println(remain.toString() + ": "
								+ DataUtil.byteArrayToString(remain.getBytes()));
					}
					response = this.channel.transmit(remain);
				} else {
					CommandAPDU remain = new CommandAPDU(0x00, 0xc0, 0x00,
							0x00, SW2);
					if (debug) {
						System.out.println(remain.toString() + ": "
								+ DataUtil.byteArrayToString(remain.getBytes()));
					}
					response = this.channel.transmit(remain);
				}
				if (debug) {
					System.out
							.println(response.toString()
									+ ": "
									+ DataUtil.byteArrayToString(response
											.getData()));
				}
				rbaos.write(response.getData());
				SW1 = response.getSW1();
				SW2 = response.getSW2();
			}
			TLV pcaptmpl = new TLV(response.getData());
			this.pcap = new PIVCardApplicationProperty(pcaptmpl.getValue());
		} else if (status_word == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
			if (debug) {
				System.out.println(response.toString() + ": "
						+ DataUtil.byteArrayToString(response.getData()));
			}
			if (response.getData().length  <= 0) {
				if (debug) {
					System.out.println("Response APDU is empty, should contain App Prop.");
				}
			} else {
				TLV pcaptmpl = new TLV(response.getData());
				this.pcap = new PIVCardApplicationProperty(pcaptmpl.getValue());
			}
		}
		if (debug) {
			if (this.getPIVCardApplicationProperty() != null) {
				System.out.println("Application Property:\n" + this.getPIVCardApplicationProperty().toString());
			}
		}

		// Perform a GET-DATA command to obtain to get the Discovery Object
		command = PIVAPDU.getPIVData(new Tag(Tag.PIV_DISCOVERY_OBJECT));
		response = this.channel.transmit(command);
		if (response.getSW() == 0x9000) {
			this.pdo = new PIVDiscoveryObject(response.getData());
			this.setHasDiscoveryObject(true);
			if (debug) {
				System.out.println(this.pdo.toString());
			}
		} else {
			this.pdo = null;
			this.setHasDiscoveryObject(false);
		}
		this.auth = Auth.NONE;
	}

	/**
	 * Method disconnect.
	 * @param reset boolean
	 * @throws CardException
	 */
	public void disconnect(boolean reset) throws CardException {
		this.card.disconnect(reset);
	}

	/**
	 * Method getAdminAuthenticatedChannel.
	 * @param keyStore KeyStore
	 * @param keyAlias String
	 * @param password char[]
	 * @param diversified boolean
	 * @param divData byte[]
	 * @throws CardException
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableKeyException
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public void getAdminAuthenticatedChannel(KeyStore keyStore,
			String keyAlias, char[] password, boolean diversified, byte[] divData) throws CardException,
			IOException, KeyStoreException, NoSuchAlgorithmException,
			UnrecoverableKeyException, InvalidKeyException, InvalidKeySpecException {

		CardChannel adminAuthenticatedChannel = this.channel;

		// Currently, only the following Admin Auth is supported:
		// algRef=CipherEngine.THREE_KEY_3DES_ECB &&
		// keyRef=CipherEngine.CARD_MGMT_KEY
		
		

		// Select the PIV application
		ResponseAPDU response = adminAuthenticatedChannel.transmit(PIVAPDU
				.selectPIVApplication());


			if (debug) {
				System.out.println("General Auth Request.");
			}

			DynamicAuthTempl gaReq = new DynamicAuthTempl(
					DynamicAuthTempl.POP_TO_CARD_SYM_CHAL_REQ, null);
			Enumeration<CommandAPDU> gaapdus = PIVAPDU.generalAuthenticate(
					CipherEngine.THREE_KEY_3DES_ECB,
					CipherEngine.CARD_MGMT_KEY, gaReq.getEncoded());
			CommandAPDU gaapdu;
			while (gaapdus.hasMoreElements()) {
				gaapdu = gaapdus.nextElement();
				if (debug) {
					System.out.println("PUT APDU: " + gaapdu.toString());
					System.out.println("PUT APDU: "
							+ DataUtil.byteArrayToString(gaapdu.getBytes()));
				}
				response = adminAuthenticatedChannel.transmit(gaapdu);
				if (debug) {
					// Show response from last command APDU
					System.out.println(response.toString() + ":\n"
							+ DataUtil.byteArrayToString(response.getData()));
				}
			}
			DynamicAuthTempl gaResp = new DynamicAuthTempl(response.getData());

			if (debug) {
				System.out.println(gaResp.toString());
			}

			SecretKey PIV_ADM_KEY = KeyStoreManager.getSecretKey(keyStore,
					keyAlias, password);

			if (diversified) {
				byte[] divKey = CipherEngine.TDES198ECB(divData, PIV_ADM_KEY, CipherEngine.ENCRYPT_MODE);
				DESedeKeySpec ks = new DESedeKeySpec(divKey);
				SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
				PIV_ADM_KEY = kf.generateSecret(ks);
			}

			if (debug) {
				System.out.println("General Auth Response.");
			}

			DynamicAuthTempl gaAuthResp = new DynamicAuthTempl(
					DynamicAuthTempl.POP_TO_CARD_SYM, CipherEngine.TDES198ECB(
							gaResp.getTemplateValue(), PIV_ADM_KEY,
							CipherEngine.ENCRYPT_MODE));
			gaapdus = PIVAPDU.generalAuthenticate(
					CipherEngine.THREE_KEY_3DES_ECB,
					CipherEngine.CARD_MGMT_KEY, gaAuthResp.getEncoded());
			while (gaapdus.hasMoreElements()) {
				gaapdu = gaapdus.nextElement();
				if (debug) {
					System.out.println("PUT APDU: " + gaapdu.toString());
					System.out.println("PUT APDU: "
							+ DataUtil.byteArrayToString(gaapdu.getBytes()));
				}
				response = adminAuthenticatedChannel.transmit(gaapdu);
				if (debug) {
					// Show response from last command APDU
					System.out.println(response.toString() + ":\n"
							+ DataUtil.byteArrayToString(response.getData()));
				}
			}
			if (response.getSW() == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
				this.auth = Auth.ADMIN;
				this.channel = adminAuthenticatedChannel;
				System.gc();
			} else {
				if (debug) {
					System.out
							.println("Admin Authentication failed! Response: ");
					System.out.println(response.toString() + ":\n"
							+ DataUtil.byteArrayToString(response.getData()));
				}
			}
	}

	/*
	 * The following methods provide a card channel to a PIV applet that is
	 * already selected.
	 * 
	 * The intent is to provide independent channels to the card based on the
	 * authentication level, however the underlying Sun provider makes use of
	 * the same channel from any given Terminal object using
	 * Card.getBasicChannel(). This remains true even if new Terminal and Card
	 * objects are created. The only way to separate the channels is if there
	 * were support for logical channels, which appear to be card dependent.
	 * Therefore, the following methods exist to promote the privileges of the
	 * existing channel when needed, and this SHOULD be the only object used by
	 * relying applications to promote the authentication level. At this time,
	 * there is no technical enforcement.
	 */

	/**
	 * Method getATR.
	 * @return ATR
	 */
	public ATR getATR() {
		return this.card.getATR();
	}

	/**
	 * Method getCardAuthCert.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getCardAuthCert() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_CERT_CARDAUTH));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getCardCapabilityContainer.
	 * @return PIVCardCapabilityContainer
	 * @throws CardException
	 */
	public PIVCardCapabilityContainer getCardCapabilityContainer()
			throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_CCC));
		return new PIVCardCapabilityContainer(data.getData());
	}

	/**
	 * Method getCardHolderUniqueID.
	 * @return PIVCardHolderUniqueID
	 * @throws CardException
	 */
	public PIVCardHolderUniqueID getCardHolderUniqueID() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_CHUID));
		return new PIVCardHolderUniqueID(data.getData());
	}

	/**
	 * Method getChannel.
	 * @return CardChannel
	 */
	public CardChannel getChannel() {
		return this.channel;
	}

	/*
	 * The following methods provide a way to read and write objects to the PIV
	 * applet.
	 * 
	 * Access conditions to each of the objects should be evaluated prior to the
	 * requests being made.
	 * 
	 * Ref 800-73-3, Part 1, Table 6
	 */

	/**
	 * Method getDigSigCert.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getDigSigCert() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_CERT_DIGSIG));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getDiscoveryObject.
	 * @return PIVDiscoveryObject
	 * @throws CardException
	 */
	public PIVDiscoveryObject getDiscoveryObject() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_DISCOVERY_OBJECT));
		return new PIVDiscoveryObject(data.getData());
	}

	/**
	 * Method getFacialImage.
	 * @return PIVCardHolderFacialImage
	 * @throws CardException
	 */
	public PIVCardHolderFacialImage getFacialImage() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(
				Tag.PIV_CARDHOLDER_FACIAL_IMAGE));
		return new PIVCardHolderFacialImage(data.getData());
	}

	/**
	 * Method getFingerprints.
	 * @return PIVCardHolderFingerprints
	 * @throws CardException
	 */
	public PIVCardHolderFingerprints getFingerprints() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(
				Tag.PIV_CARDHOLDER_FINGERPRINTS));
		return new PIVCardHolderFingerprints(data.getData());
	}

	/**
	 * Method getIrisImages.
	 * @return PIVCardHolderIrisImages
	 * @throws CardException
	 */
	public PIVCardHolderIrisImages getIrisImages() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(
				Tag.PIV_CARDHOLDER_IRIS_IMAGES));
		return new PIVCardHolderIrisImages(data.getData());
	}

	/**
	 * Method getKeyEnciphermentCert.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getKeyEnciphermentCert() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_CERT_KEYMGMT));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getKeyHistoryObject.
	 * @return PIVKeyHistoryObject
	 * @throws CardException
	 */
	public PIVKeyHistoryObject getKeyHistoryObject() throws CardException {
		PIVDataTempl data = this
				.getPIVData(new Tag(Tag.PIV_KEY_HISTORY_OBJECT));
		return new PIVKeyHistoryObject(data.getData());
	}

	/**
	 * Method getOpenChannel.
	 * @throws CardException
	 */
	public void getOpenChannel() throws CardException {
		CardChannel openChannel = this.channel;

		// Select the PIV application
		ResponseAPDU response = openChannel.transmit(PIVAPDU
				.selectPIVApplication());
		this.pcap = new PIVCardApplicationProperty(response.getData());

		this.auth = Auth.NONE;

		this.channel = openChannel;

	}

	/**
	 * Method getPIVAuthCert.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getPIVAuthCert() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_CERT_PIVAUTH));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getPIVCardApplicationProperty.
	 * @return PIVCardApplicationProperty
	 */
	public PIVCardApplicationProperty getPIVCardApplicationProperty() {
		return this.pcap;
	}

	/**
	 * Method getPIVData.
	 * @param pivObjectTag Tag
	 * @return PIVDataTempl
	 * @throws CardException
	 */
	private PIVDataTempl getPIVData(Tag pivObjectTag) throws CardException {
		PIVDataTempl data = null;
		try {
			CommandAPDU command = PIVAPDU.getPIVData(pivObjectTag);
			if (debug) {
				System.out.println(command.toString() + ": "
						+ DataUtil.byteArrayToString(command.getBytes()));
			}
			ResponseAPDU response = this.channel.transmit(command);
			int status_word = response.getSW();
			int SW1 = response.getSW1();
			int SW2 = response.getSW2();
			if (SW1 == 0x61) {
				ByteArrayOutputStream rbaos = new ByteArrayOutputStream();
				if (debug) {
					System.out.println(response.toString() + ": "
							+ DataUtil.byteArrayToString(response.getData()));
				}
				rbaos.write(response.getData());
				while (SW1 == 0x61) {
					// Craft a GET-DATA APDU to collect the bytes remaining
					if (SW2 == 0x00) {
						CommandAPDU remain = new CommandAPDU(
								DataUtil.stringToByteArray("00C0000000"));
						if (debug) {
							System.out.println(remain.toString() + ": "
									+ DataUtil.byteArrayToString(remain.getBytes()));
						}
						response = this.channel.transmit(remain);
					} else {
						CommandAPDU remain = new CommandAPDU(0x00, 0xc0, 0x00,
								0x00, SW2);
						if (debug) {
							System.out.println(remain.toString() + ": "
									+ DataUtil.byteArrayToString(remain.getBytes()));
						}
						response = this.channel.transmit(remain);
					}
					if (debug) {
						System.out
								.println(response.toString()
										+ ": "
										+ DataUtil.byteArrayToString(response
												.getData()));
					}
					rbaos.write(response.getData());
					SW1 = response.getSW1();
					SW2 = response.getSW2();
				}
				data = new PIVDataTempl(rbaos.toByteArray());
			} else if (status_word == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
				data = new PIVDataTempl(response.getData());
			} else if (status_word == PIVAPDUInterface.PIV_SW_OBJECT_OR_APPLICATION_NOT_FOUND) {
				throw new CardException("Object not found: Tag: " + DataUtil.byteArrayToString(pivObjectTag.getBytes()));
			} else if (status_word == PIVAPDUInterface.PIV_SW_SECURITY_CONDITION_NOT_SATISFIED) {
				throw new CardException("Authentication required!");
			} else {
				throw new CardException(response.toString());
			}
		} catch (java.io.IOException ex) {
			throw new CardException(ex);
		}
		return data;
	}

	/**
	 * Method putPIVData.
	 * @param pivObjectTag Tag
	 * @param pivData byte[]
	 * @throws CardException
	 * @throws IOException 
	 */
	public void putPIVData(Tag pivObjectTag, byte[] pivData) throws CardException, IOException {
		Enumeration<CommandAPDU> commands = PIVAPDU.putPIVData(pivObjectTag, pivData);
		CommandAPDU command;
		ResponseAPDU response;
		while (commands.hasMoreElements()) {
			command = commands.nextElement();
			if (debug) {
				System.out.println("PUT APDU: " + command.toString());
				System.out.println("PUT APDU: " + DataUtil.byteArrayToString(command.getData()));
			}
			response = this.channel.transmit(command);
			if (debug) {
				System.out.println(response.toString() + ":\n" + DataUtil.byteArrayToString(response.getData()));
			}
		}
	}

	/**
	 * Method getPrintedInformation.
	 * @return PIVPrintedInformation
	 * @throws CardException
	 */
	public PIVPrintedInformation getPrintedInformation() throws CardException {
		PIVDataTempl data = this
				.getPIVData(new Tag(Tag.PIV_PRINTED_INFORMATION));
		return new PIVPrintedInformation(data.getData());
	}

	/**
	 * Method getRetiredCert01.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert01() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM01));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert02.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert02() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM02));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert03.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert03() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM03));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert04.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert04() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM04));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert05.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert05() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM05));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert06.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert06() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM06));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert07.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert07() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM07));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert08.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert08() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM08));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert09.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert09() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM09));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert10.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert10() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM10));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert11.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert11() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM11));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert12.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert12() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM12));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert13.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert13() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM13));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert14.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert14() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM14));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert15.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert15() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM15));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert16.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert16() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM16));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert17.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert17() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM17));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert18.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert18() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM18));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert19.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert19() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM19));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getRetiredCert20.
	 * @return PIVCertificate
	 * @throws CardException
	 */
	public PIVCertificate getRetiredCert20() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_RET_CERT_KM20));
		return new PIVCertificate(data.getData());
	}

	/**
	 * Method getSecurityObject.
	 * @return PIVSecurityObject
	 * @throws CardException
	 */
	public PIVSecurityObject getSecurityObject() throws CardException {
		PIVDataTempl data = this.getPIVData(new Tag(Tag.PIV_SECURITY_OBJECT));
		return new PIVSecurityObject(data.getData());
	}

	/**
	 * Method getUserAuthenticatedChannel.
	 * @param pin byte[]
	 * @throws CardException
	 * @throws IOException
	 */
	public void getUserAuthenticatedChannel(byte[] pin)
			throws CardException, IOException {
		CardChannel userAuthenticatedChannel = this.channel;
		ResponseAPDU response;

		// Select the PIV application
		response = userAuthenticatedChannel.transmit(PIVAPDU
				.selectPIVApplication());

			while (this.auth != Auth.USER) {

				// Default to the application PIN, then check for a PIN Policy.
				byte keyRef = Tag.PIV_APPLICATION_PIN;
				if (this.pdo != null) {
					if (this.pdo.globalPINPrimary()) {
						keyRef = Tag.PIV_GLOBAL_PIN;
					}
				}

				if (debug) {
					response = userAuthenticatedChannel.transmit(PIVAPDU
							.pinVerifyAPDU(keyRef, true, null));
					System.out.println("Checking PIN Reference: Response APDU:"
							+ response.toString());
				}

				response = userAuthenticatedChannel.transmit(PIVAPDU
						.pinVerifyAPDU(keyRef, false, pin));
				if (response.getSW() == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
					this.auth = Auth.USER;
					this.channel = userAuthenticatedChannel;
					System.gc();
				} else if (response.getSW() == PIVAPDUInterface.PIV_SW_AUTHENTICATION_METHOD_BLOCKED) {
					throw new CardBlockedException("Card is blocked.");
				} else if (response.getSW1() == 0x63) {
					throw new InvalidPinException("Invalid pin.", (response.getSW2() & 0x0F));
				}
			}
	}

	/**
	
	 * @return the hasDiscoveryObject */
	public boolean hasDiscoveryObject() {
		return this.hasDiscoveryObject;
	}

	/**
	 * @param hasDiscoveryObject
	 *            the hasDiscoveryObject to set
	 */
	private void setHasDiscoveryObject(boolean hasDiscoveryObject) {
		this.hasDiscoveryObject = hasDiscoveryObject;
	}

}