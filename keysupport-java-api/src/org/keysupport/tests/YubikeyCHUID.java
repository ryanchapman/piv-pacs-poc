package org.keysupport.tests;
/******************************************************************************
 *
 * ====BEGIN RAC NOTES====
 * This is a quick+dirty program to generate a signed CHUID based on the
 * org.keysupport.tests.CHUIDTest program.
 *
 * NOTE: It only supports ECC P-256 certificate authorities, not RSA.
 *       Pretty simple to add though, as this originally only supported RSA.
 *       Problem with RSA is that an RSA signed CHUID will not fit in the
 *       Yubikey's CHUID container (0x3000, 0x5fc102).
 *       Supposedly, the Yubikey NEO 4 will have a CHUID container large
 *       enough to put a 2048-bit RSA signed CHUID.  1024-bit RSA is not
 *       allowed per FIPS201.
 *
 * Ryan A. Chapman, ryan@rchapman.org
 * Sun Jan 24 21:04:32 MST 2016
 *
 * ====END RAC NOTES====
 *
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
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
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
public class YubikeyCHUID {

	/*****************************************************************************
	 * Reference: NIST SP 800-73-3, Part(s) 1 & 2
	 *
	 * Full debugging: java -Xmx512m -Djava.security.debug=all PIVTest The
	 * memory is so high to support PDVal testing if the cert path is verified.
	 * @param args String[]
	 ****************************************************************************/

	public static void main(String args[]) {
        if (args.length != 2) {
            System.out.println("usage: YubikeyCHUID guid output_file\n");
            System.out.println("       guid         GUID to use in the CHUID. Note this must also be encoded in certificates.\n");
            System.out.println("       output_file  file where encoded CHUID will be written\n");
            System.out.println("       You can then use yubico-piv-tool to write the CHUID to the Yubikey NEO");
            System.out.println("       YubikeyCHUID 6a9f4f08-3166-9177-7f15-de4d3ac36fef chuid_file.hex");
            System.out.println("       yubico-piv-tool -a write-object 0x5fc102 -i chuid_file.hex\n");
            System.exit(1);
        }
		//Perform the read and validation test
		//readAndValidate();
		//Perform the create and validation test
		//createAndValidate();
        String guid = args[0];
        String outputFile = args[1];
        createAndWrite(guid, outputFile);
	}

	public static void createAndWrite(String guidString, String outputFile) {
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

            // Expire in 20 years
			Calendar expirydate = Calendar.getInstance();
            expirydate.add(Calendar.YEAR, 20);
			String expiry = DataUtil.dateToString(expirydate.getTime());

			//Create GUID bytes from a random UUID
			//UUID uuid = UUID.randomUUID();
            UUID uuid = UUID.fromString(guidString);
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
                System.out.println("Writing CHUID to file '" + outputFile + "'");
                writeCHUIDToFile(baos2.toByteArray(), outputFile);
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

    private static void writeCHUIDToFile(byte[] chuidByteArray, String chuidFilename) {
        try {
            PrintWriter chuidFile = new PrintWriter(chuidFilename);
            // yubico-piv-tool will add a 53 TLV, so we must skip it here
            // if we encounter a tag of 53, then skip the Tag and Length, leaving only the Value
            // see BER-TLV encoding of length values 81, 82, 83, and 84 to find why we skip the amt we do below
            int skip=0;
            if (chuidByteArray[0] == 0x53) {
                switch(chuidByteArray[1]) {          // length (L) part of TLV
                    case (byte)0x81:
                        skip = 3;
                        break;
                    case (byte)0x82:
                        skip = 4;
                        break;
                    case (byte)0x83:
                        skip = 5;
                        break;
                    case (byte)0x84:
                        skip = 6;
                        break;
                    default:
                        String errmsg = String.format("In initial 0x53 tag of CHUID, the length 0x%X is not valid. (Valid values are 0x81, 082, 0x83, and 0x84)");
                        throw new Exception(errmsg);
                }
            }
            ByteBuffer doctoredCHUIDByteBuffer = ByteBuffer.wrap(chuidByteArray, skip, chuidByteArray.length-skip);
            byte[] finalCHUIDByteArray = new byte[chuidByteArray.length-skip];
            doctoredCHUIDByteBuffer.get(finalCHUIDByteArray);
            chuidFile.print(DataUtil.byteArrayToString(finalCHUIDByteArray));
            chuidFile.close();
        } catch(FileNotFoundException e) {
            System.err.println("File not found '" + chuidFilename);
            e.printStackTrace();
        } catch(Throwable e) {
            e.printStackTrace();
        }

    }

}
