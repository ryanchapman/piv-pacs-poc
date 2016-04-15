/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: GetCHUIDTimed.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.tests;

import java.security.AccessController;
import java.security.PrivilegedAction;

import org.keysupport.nist80073.PIVCard;
import org.keysupport.nist80073.datamodel.CMSSignedDataObject;
import org.keysupport.nist80073.datamodel.PIVCardHolderUniqueID;
import org.keysupport.smartcardio.CardTerminal;
import org.keysupport.util.DataUtil;
import org.keysupport.util.TimestampPrintStream;

/**
 */
public class GetCHUIDTimed {

	private static boolean debug = true;
	
	/**
	 * Method main.
	 * @param args String[]
	 */
	public static void main(String args[]){
		try {
			//Set up our reader/terminal
			CardTerminal terminal = new CardTerminal();
			
			//Set up timed tracing output
			if (debug) {
				AccessController.doPrivileged(new PrivilegedAction<Void>() {
					@Override
					public Void run() {
						System.setProperty("java.security.debug", "all");
						System.setOut(new TimestampPrintStream(System.err));
						System.setErr(new TimestampPrintStream(System.out));
						return null;
					}
				});
			}
			// Establish a connection with the card
			PIVCard card = terminal.getPIVCard();
			//Print the ATR of the card
			System.out.println("Card ATR: "
					+ DataUtil.byteArrayToString(card.getATR().getBytes()));
			// Get the PIV CHUID
			PIVCardHolderUniqueID chuid = card.getCardHolderUniqueID();
			// Disconnect from the card, we'll keep working with the CHUID
			card.disconnect(false);
			//Print out the CHUID Contents
			System.out.println(chuid.toString());
			//Verify the digital signature, and print the result
			System.out.println("Verifying CHUID Signature:");
			CMSSignedDataObject chuidSig = new CMSSignedDataObject(
					chuid.getSignatureBytes(), chuid.getSignatureDataBytes());
			if (chuidSig.verifySignature(true)) {
				System.out.println("Signature Verified!");
			} else {
				System.out.println("Signature Verification Failed!");
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}		
	}
	
}
