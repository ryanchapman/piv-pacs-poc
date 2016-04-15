/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVReadTest.java 25 2014-07-08 17:02:30Z grandamp@gmail.com $
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
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import org.keysupport.nist80073.CardBlockedException;
import org.keysupport.nist80073.InvalidPinException;
import org.keysupport.nist80073.PIVCard;
import org.keysupport.nist80073.datamodel.CMSSignedDataObject;
import org.keysupport.nist80073.datamodel.PIVCardCapabilityContainer;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.nist80073.datamodel.PIVKeyHistoryObject;
import org.keysupport.nist80073.datamodel.PIVPrintedInformation;
import org.keysupport.nist80073.datamodel.PIVSecurityObject;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVReadTest {

/*****************************************************************************
 * Reference:  NIST SP 800-73-3, Part(s) 1 & 2
 *
 * This example highlights the need to change exception handling
 * on objects that are not found, so the remainder of the code will
 * continue.
 * 
 * In this case, if the Key History Object is not populated, an exception
 * will be thrown and the remainder of the code will fail to execute.
 *
 * @param args String[]
 ****************************************************************************/

	public static void main(String args[]) {
		try {

			System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
			System.setProperty("sun.security.smartcardio.t1GetResponse", "false");

			System.out.println("- KeySupport PIV API Read Test -\n");
			//Show the list of available terminals
			TerminalFactory factory = TerminalFactory.getDefault();
			System.out.println("Provider: " + factory.getProvider().getName() + " - " + factory.getProvider().getInfo());
			List<CardTerminal> terminals = factory.terminals().list();
			System.out.println("Available Card Readers:\n");
			for (int i = 0; i < terminals.size(); i++){
				CardTerminal term = terminals.get(i);
				int dnum = i + 1;
				System.out.println(dnum + ": " + term.getName());
			}
			System.out.println("\nEnter a number of the reader which contains the PIV credential,");
			System.out.println("and then press [Enter]:");
			BufferedReader input =
			  new BufferedReader(new InputStreamReader(System.in));
			int reader_num = 1;
			reader_num = Integer.parseInt(input.readLine());
			input.close();

			//Get the identified terminal
			CardTerminal terminal = terminals.get(reader_num-1);

			//Establish a connection with the card
			PIVCard card = new PIVCard(terminal.connect("*"));
			System.out.println("Card: " + card);
			System.out.println("Card ATR: " + DataUtil.byteArrayToString(card.getATR().getBytes()));

			try {

				//Get the PIV CHUID
				PIVCardHolderUniqueID chuid = card.getCardHolderUniqueID();
				//Process CHUID
				System.out.println(chuid.toString());
				CMSSignedDataObject chuidSig = new CMSSignedDataObject(chuid.getSignatureBytes(), chuid.getSignatureDataBytes());
				boolean verifysigs = false;
				if (verifysigs) {
					//Verify CHUID Signature
					if (chuidSig.verifySignature(false)) {
						System.out.println("Signature Verified");
					} else {
						System.out.println("Signature Verification Failed!");
					}
				}
				//Get the content signing cert from the CHUID for validation of other objects
				X509Certificate PIVContentSigner = chuidSig.getSigner();
				System.out.println("PIV Content Signing Certificate from CHUID:\n" + PIVContentSigner.toString());

				//Get the PIVAuth Cert
				PIVCertificate cardAuth = card.getPIVAuthCert();
				System.out.println(cardAuth.toString());
				System.out.println("PIV Auth Certificate:\n" + cardAuth.getCertificate().toString());

				//Get the CCC
				PIVCardCapabilityContainer ccc = card.getCardCapabilityContainer();
				System.out.println(ccc.toString());

				//Get the ICAO Security Object
				PIVSecurityObject so = card.getSecurityObject();
				System.out.println(so.toString());

				//Get the keyHistory object
				PIVKeyHistoryObject kh = card.getKeyHistoryObject();
				System.out.println(kh.toString());

				//Obtain a User authenticated channel
				card.getUserAuthenticatedChannel(getPIVPIN("Credential PIN:"));

				//Get the printed information
				PIVPrintedInformation pi = card.getPrintedInformation();
				System.out.println(pi.toString());

			} catch(CardBlockedException e) {
				System.out.println("Your card is locked.");
			} catch(InvalidPinException e) {
				System.out.println(e.getLocalizedMessage());
			} catch(CardException e) {
				System.out.println(e.getLocalizedMessage());
			}

			//Disconnect
			card.disconnect(false);

		}catch(Throwable e) {
			e.printStackTrace();
		}
	}

    /**************************************************************************
     * PIN Prompting method
     *
     * This is a utility method that makes use of Java Swing components to
     * obtain a PIV PIN.
     * @param dialog_label String
     * @return byte[]
     *************************************************************************/
    public static byte[] getPIVPIN(String dialog_label) {
            char[] pin = getPIN(dialog_label);
            byte[] pinbytes = new byte[pin.length];
            for (int i = 0; i < pinbytes.length; i++) {
                    pinbytes[i] = (byte)pin[i];
                    pin[i] = (char)0x00;
            }
            return DataUtil.pad(pinbytes, (byte)0xff, 8);
    }

    /**************************************************************************
     * PIN/Password Prompting method
     *
     * This is a utility method that makes use of Java Swing components to
     * obtain general token activation data. (PIN or Password)
     * @param dialog_label String
     * @return char[]
     *************************************************************************/
    public static char[] getPIN(String dialog_label) {
            char[] pin = null;
            while (pin == null) {
                    final JPasswordField jpf = new JPasswordField();
                    JOptionPane jop = new JOptionPane(jpf, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
                    JDialog dialog = jop.createDialog(dialog_label);
                    dialog.setVisible(true);
                    int result = (Integer)jop.getValue();
                    dialog.dispose();
                    if(result == JOptionPane.OK_OPTION){
                            pin = jpf.getPassword();
                    }
            }
            return pin;
    }

}
