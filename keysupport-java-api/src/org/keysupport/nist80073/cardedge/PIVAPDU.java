/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVAPDU.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.nist80073.cardedge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

import javax.smartcardio.CommandAPDU;

import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 * @author tejohnson
 * 
 * @version $Revision: 3 $
 */
public class PIVAPDU {

	private final static boolean debug = true;

	// No support at this time for extended length APDUs
	public final static int MAX_APDU_SIZE = 255;

	/**
	 * Method clearPIVData.
	 * @param pivObjectTag Tag
	 * @return CommandAPDU
	 * @throws IOException
	 */
	public static CommandAPDU clearPIVData(Tag pivObjectTag) throws IOException {
		Enumeration<CommandAPDU> apdus = putPIVData(pivObjectTag, null);
		return apdus.nextElement();
	}

	/**
	 * Method generalAuthenticate.
	 * @param algRef byte
	 * @param keyRef byte
	 * @param dat byte[]
	 * @return Enumeration<CommandAPDU>
	 * @throws IOException
	 */
	public static Enumeration<CommandAPDU> generalAuthenticate(byte algRef,
			byte keyRef, byte[] dat) throws IOException {
		byte[] apdu_data;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Vector<CommandAPDU> apdus = new Vector<CommandAPDU>();

		apdu_data = dat;

		// TODO: Fix command chaining for additional auth methods: Ref:
		// 800-73-3, Part 2, Section 3.2.4
		if ((apdu_data.length) >= MAX_APDU_SIZE) {
			baos.write(PIVAPDUInterface.PIV_GEN_AUTH_CC_HEADER);
			baos.write(algRef);
			baos.write(keyRef);
			baos.write(MAX_APDU_SIZE - 5);
			baos.write(apdu_data);
			apdu_data = baos.toByteArray();
			baos.reset();
			byte[][] cc_apdu_data = DataUtil.getArrays(apdu_data,
					MAX_APDU_SIZE, false);
			for (int i = 0; i < cc_apdu_data.length; i++) {
				if (i == 0) {
					baos.write(cc_apdu_data[i]);
					if (debug) {
						System.out
								.println("Adding APDU: "
										+ DataUtil.byteArrayToString(baos
												.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				} else if (i == (cc_apdu_data.length - 1)) {
					baos.write(PIVAPDUInterface.PIV_GEN_AUTH_HEADER);
					baos.write(algRef);
					baos.write(keyRef);
					baos.write(cc_apdu_data[i].length);
					baos.write(cc_apdu_data[i]);
					baos.write((byte)0x00);  //Add Le
					if (debug) {
						System.out
								.println("Adding APDU: "
										+ DataUtil.byteArrayToString(baos
												.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				} else {
					baos.write(PIVAPDUInterface.PIV_GEN_AUTH_CC_HEADER);
					baos.write(algRef);
					baos.write(keyRef);
					baos.write(cc_apdu_data[i].length);
					baos.write(cc_apdu_data[i]);
					if (debug) {
						System.out
								.println("Adding APDU: "
										+ DataUtil.byteArrayToString(baos
												.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				}
			}
		} else {
			// Typically the case when algRef=CipherEngine.THREE_KEY_3DES_ECB &&
			// keyRef=CipherEngine.CARD_MGMT_KEY
			baos.write(PIVAPDUInterface.PIV_GEN_AUTH_HEADER);
			baos.write(algRef);
			baos.write(keyRef);
			baos.write(dat.length);
			baos.write(dat);
			apdus.add(new CommandAPDU(baos.toByteArray()));
		}
		Enumeration<CommandAPDU> apduse = apdus.elements();
		return apduse;
	}

	/**
	 * Method genRSAKeyPair.
	 * @param chaining boolean
	 * @param keyRef byte
	 * @param keySize byte
	 * @param pubExponent byte[]
	 * @return CommandAPDU
	 * @throws IOException
	 */
	public static CommandAPDU genRSAKeyPair(boolean chaining, byte keyRef,
			byte keySize, byte[] pubExponent) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		if (chaining) {
			baos.write(PIVAPDUInterface.PIV_GEN_ASYM_KP_CC_HEADER);
		} else {
			baos.write(PIVAPDUInterface.PIV_GEN_ASYM_KP_HEADER);
		}
		baos.write(keyRef);
		AsymmetricKeyRefTempl ak = new AsymmetricKeyRefTempl(keySize,
				pubExponent);
		byte[] data = ak.getEncoded();
		baos.write(data.length);
		baos.write(data);
		return new CommandAPDU(baos.toByteArray());
	}

	/**
	 * Method getPIVData.
	 * @param pivObjectTag Tag
	 * @return CommandAPDU
	 * @throws IOException
	 */
	public static CommandAPDU getPIVData(Tag pivObjectTag) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] tag_bytes = pivObjectTag.getBytes();
		baos.write(PIVAPDUInterface.PIV_GET_DATA_HEADER);
		baos.write(tag_bytes.length + 2);
		baos.write((byte) 0x5c);
		baos.write(tag_bytes.length);
		baos.write(tag_bytes);
		baos.write(0x00);
		if (debug) {
			System.out.println("Command APDU: "
					+ DataUtil.byteArrayToString(baos.toByteArray()));
		}
		return new CommandAPDU(baos.toByteArray());
	}

	/**
	 * Method pinVerifyAPDU.
	 * @param keyRef byte
	 * @param statusCheck boolean
	 * @param pin byte[]
	 * @return CommandAPDU
	 * @throws IOException
	 */
	public static CommandAPDU pinVerifyAPDU(byte keyRef, boolean statusCheck,
			byte[] pin) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(PIVAPDUInterface.PIV_VERIFY_HEADER);
		baos.write(keyRef);
		if (statusCheck) {
			baos.write((byte) 0x00);
		} else {
			baos.write(pin.length);
			baos.write(pin);
		}
		return new CommandAPDU(baos.toByteArray());
	}

	/**
	 * Method putPIVData.
	 * @param pivObjectTag Tag
	 * @param data byte[]
	 * @return Enumeration<CommandAPDU>
	 * @throws IOException
	 */
	public static Enumeration<CommandAPDU> putPIVData(Tag pivObjectTag,
			byte[] data) throws IOException {
		byte[] apdu_data;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Vector<CommandAPDU> apdus = new Vector<CommandAPDU>();

		// Determine data object
		PIVDataTempl _data = new PIVDataTempl(pivObjectTag, data);
		apdu_data = _data.getEncoded();

		// Determine lenght of the data object and build the APDUs accordingly
		if ((apdu_data.length) >= MAX_APDU_SIZE) {
			baos.write(PIVAPDUInterface.PIV_PUT_DATA_CC_HEADER);
			baos.write(MAX_APDU_SIZE - 5);
			baos.write(apdu_data);
			apdu_data = baos.toByteArray();
			baos.reset();
			byte[][] cc_apdu_data = DataUtil.getArrays(apdu_data,
					MAX_APDU_SIZE, false);
			for (int i = 0; i < cc_apdu_data.length; i++) {
				if (i == 0) {
					baos.write(cc_apdu_data[i]);
					if (debug) {
						System.out
								.println("Adding APDU: "
										+ DataUtil.byteArrayToString(baos
												.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				} else if (i == (cc_apdu_data.length - 1)) {
					baos.write(PIVAPDUInterface.PIV_PUT_DATA_HEADER);
					baos.write(cc_apdu_data[i].length);
					baos.write(cc_apdu_data[i]);
					if (debug) {
						System.out
								.println("Adding APDU: "
										+ DataUtil.byteArrayToString(baos
												.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				} else {
					baos.write(PIVAPDUInterface.PIV_PUT_DATA_CC_HEADER);
					baos.write(cc_apdu_data[i].length);
					baos.write(cc_apdu_data[i]);
					if (debug) {
						System.out
								.println("Adding APDU: "
										+ DataUtil.byteArrayToString(baos
												.toByteArray()));
					}
					apdus.add(new CommandAPDU(baos.toByteArray()));
					baos.reset();
				}
			}
		} else {
			baos.write(PIVAPDUInterface.PIV_PUT_DATA_HEADER);
			baos.write(apdu_data.length);
			baos.write(apdu_data);
			apdus.add(new CommandAPDU(baos.toByteArray()));
			baos.reset();
		}
		Enumeration<CommandAPDU> apduse = apdus.elements();
		return apduse;
	}

	/**
	 * Method selectPIVApplication.
	 * @return CommandAPDU
	 */
	public static CommandAPDU selectPIVApplication() {
		return new CommandAPDU(PIVAPDUInterface.SELECT_PIV);
	}

}