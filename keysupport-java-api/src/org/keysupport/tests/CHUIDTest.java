package org.keysupport.tests;
/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 *
 * $Id: CHUIDTest.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.UUID;

import org.keysupport.keystore.KeyStoreManager;
import org.keysupport.nist80073.PIVCard;
import org.keysupport.nist80073.datamodel.CMSSignedDataObject;
import org.keysupport.nist80073.datamodel.FASCN;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;
import org.keysupport.smartcardio.CardTerminal;
import org.keysupport.util.DataUtil;

import java.io.ByteArrayOutputStream;
import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;

/**
 */
public class CHUIDTest {

	/*****************************************************************************
	 * Reference: NIST SP 800-73-3, Part(s) 1 & 2
	 *
	 * Full debugging: java -Xmx512m -Djava.security.debug=all PIVTest The
	 * memory is so high to support PDVal testing if the cert path is verified.
	 * @param args String[]
	 ****************************************************************************/

	public static void main(String args[]) {
		//Perform the read and validation test
		readAndValidate();
		//Perform the create and validation test
		createAndValidate();
	}

	public static void readAndValidate() {
		/*
		 * This part of the code retrieves a CHUID from a card,
		 * and validates the digital signature
		 *
		 * Begin Read & Validate
		 */
		try {
			//Set up our reader/terminal
			CardTerminal terminal = new CardTerminal();
			// Establish a connection with the card
			PIVCard card = terminal.getPIVCard();
			//Print out some information about the card
			System.out.println("Card: " + card);
			System.out.println("Card ATR: "
					+ DataUtil.byteArrayToString(card.getATR().getBytes()));
			// Get the PIV CHUID
			PIVCardHolderUniqueID chuid = card.getCardHolderUniqueID();
			// Disconnect from the card, we'll keep working with the CHUID
			card.disconnect(false);
			//Print the raw CHUID data
			System.out.println("CHUID Raw Bytes: " + DataUtil.byteArrayToString(chuid.getBytes()));
			//Print out the CHUID Contents
			System.out.println(chuid.toString());
			//Verify the digital signature, and print the result
			System.out.println("Verifying CHUID Signature:");
			CMSSignedDataObject chuidSig = new CMSSignedDataObject(
					chuid.getSignatureBytes(), chuid.getSignatureDataBytes());
			if (chuidSig.verifySignature(false)) {
				System.out.println("Signature Verified!");
			} else {
				System.out.println("Signature Verification Failed!");
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}
		/*
		 * End Read & Validate
		 */
	}

	public static void createAndValidate() {
		/*
		 * This part of the code creates a CHUID,
		 * generates the signature, presents the final CHUID,
		 * then verify's the digital signature
		 *
		 * Begin Create & Validate
		 */
		try {
			//Setup the raw FASC-N elements
			String ac = "9999"; //NSC
			String sc = "9999";
			String cn = "999999";
			String cs = "0";
			String ici = "1";
			String pi = "0000000001";
			String oc = "0";
			String oi = "0000"; //EOP
			String poa = "1";
/*            Card Holder Unique ID:FASC-N:Agency Code:           9999
                Card Holder Unique ID:FASC-N:System Code:           9999
                Card Holder Unique ID:FASC-N:Credential Number:         999999
                Card Holder Unique ID:FASC-N:Credential Series:         0
                Card Holder Unique ID:FASC-N:Individual Credential Issue:   1
                Card Holder Unique ID:FASC-N:Person Identifier:         0000000000
                Card Holder Unique ID:FASC-N:Organizational Category:       0
                Card Holder Unique ID:FASC-N:Organizational Identifier:     0000
                Card Holder Unique ID:FASC-N:Per/Org Association Category:  1
                Card Holder Unique ID:Agency Code:
                Card Holder Unique ID:Organization Identifier:
                Card Holder Unique ID:DUNS:
                Card Holder Unique ID:GUID:                 6a9f4f08-3166-9177-7f15-de4d3ac36fef
                Card Holder Unique ID:Expiration Date:              Tue Jan 01 00:00:00 MST 2030
                Card Holder Unique ID:Signature Bytes:
                Card Holder Unique ID:Error Detection Code:*/
			//Create the FASC-N
			FASCN myFASCN = new FASCN(ac, sc, cn, cs, ici, pi, oc, oi, poa);

			//Setup the raw CHUID elements

			//Let's give this CHUID a 2 week validity period
			//Calendar expirydate = Calendar.getInstance();
			//expirydate.set(Calendar.MILLISECOND, 0);
			//expirydate.add(Calendar.HOUR, 24 * 14);
			//String expiry = DataUtil.dateToString(expirydate.getTime());

            // Expire on Tue Jan 01 00:00:00 2030
            // Dec 11 22:40:39 2020
			Calendar expirydate = Calendar.getInstance();
			expirydate.set(Calendar.MILLISECOND, 0);
            expirydate.set(Calendar.SECOND, 39);
            expirydate.set(Calendar.MINUTE, 40);
			expirydate.set(Calendar.HOUR, 22);
            expirydate.set(Calendar.MONTH, Calendar.DECEMBER);
            expirydate.set(Calendar.DAY_OF_MONTH, 11);
            expirydate.set(Calendar.YEAR, 2020);
			String expiry = DataUtil.dateToString(expirydate.getTime());

			//Create GUID bytes from a random UUID
			//UUID uuid = UUID.randomUUID();
            UUID uuid = UUID.fromString("d18b1e0d-3938-4601-9f5f-b9a6d0442e4d");
			final byte[] guid = DataUtil.uuidToByteArray(uuid);

			//Create the CHUID Object containing the FASC-N, GUID, and Expiry Date
			PIVCardHolderUniqueID myCHUID = new PIVCardHolderUniqueID(myFASCN, null, null, null, guid, expiry);

			//Print out the CHUID object to show what we have so far
			System.out.println("CHUID: " + myCHUID.toString());

            // Print out the CHUID in BER-TLV encoding
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            TLV _data = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DATA), myCHUID.getBytes());
            baos.write(_data.getBytes());
            String myCHUIDByteArray = DataUtil.byteArrayToString(baos.toByteArray());
            System.out.println("CHUID encoded: " + myCHUIDByteArray.toString());

			/*
			 * Create a Fictitious PIV Content Signer Certificate and Key
			 * For now, we will use one that we have.
			 *
			 * The following values must be changed to match the keystore
			 * in your possession
			 *
			 *  ####################### BEGIN SENSITIVE #######################
			 */
			String STORENAME = "mykeystore.jks";
			String STOREPASS = "whatever";
			String ALIAS = "myservercert";

			 /*
			 *  ######################## END SENSITIVE ########################
			 */
			KeyStoreManager myKeys = new KeyStoreManager();
			KeyStore mystore = myKeys.getKeyStore(STOREPASS.toCharArray(), new File(STORENAME));
			X509Certificate signer = myKeys.getCertificate(mystore, ALIAS);
			PrivateKey signerpriv = myKeys.getPrivateKey(mystore, ALIAS, STOREPASS.toCharArray());

			//Generate the CHUID Signature
			CMSSignedDataObject myCHUIDSig = new CMSSignedDataObject(myCHUID.getSignatureDataBytes(), signer, signerpriv);
			//Add signature to CHUID
			myCHUID.setSignatureBytes(myCHUIDSig.sign());

			//Print and verify the CHUID data and signature
			PIVCardHolderUniqueID chuid = myCHUID;
			//Print out the CHUID Contents
			System.out.println(chuid.toString());

            // Print out the signed CHUID in BER-TLV encoding
            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            TLV _data2 = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_DATA), chuid.getBytes());
            baos2.write(_data2.getBytes());
            String chuidByteArray = DataUtil.byteArrayToString(baos2.toByteArray());
            System.out.println("Signed CHUID encoded: " + chuidByteArray.toString());

			//Verify the digital signature, and print the result
			System.out.println("Verifying CHUID Signature:");
			CMSSignedDataObject chuidSig = new CMSSignedDataObject(
					chuid.getSignatureBytes(), chuid.getSignatureDataBytes());
			if (chuidSig.verifySignature(false)) {
				System.out.println("Signature Verified!");
			} else {
				System.out.println("Signature Verification Failed!");
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}
		/*
		 * End Create & Validate
		 */
	}

}
