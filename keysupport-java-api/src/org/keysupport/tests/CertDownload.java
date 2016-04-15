/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CertDownload.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.keysupport.nist80073.PIVCard;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.util.DataUtil;

public class CertDownload {


	/*****************************************************************************
	 * Reference: NIST SP 800-73-3, Part(s) 1 & 2
	 * 
	 * Full debugging: java -Xmx512m -Djava.security.debug=all PIVTest The
	 * memory is so high to support PDVal testing if the cert path is verified.
	 * 
	 * @author Todd E. Johnson tejohnson@yahoo.com
	 ****************************************************************************/

	public static void main(String args[]) {
		try {

			System.out.println("- KeySupport PIV API Test-\n");
			// Show the list of available terminals
			TerminalFactory factory = TerminalFactory.getDefault();
			System.out.println("Provider: " + factory.getProvider().getName()
					+ " - " + factory.getProvider().getInfo());
			List<?> terminals = factory.terminals().list();
			System.out.println("Available Card Readers:\n");

			for (int i = 0; i < terminals.size(); i++) {
				CardTerminal term = (CardTerminal) terminals.get(i);
				int dnum = i + 1;
				System.out.println(dnum + ": " + term.getName());
			}
			
			System.out
					.println("\nEnter a number of the reader which contains the PIV credential,");
			System.out.println("and then press [Enter]:");
			BufferedReader input = new BufferedReader(new InputStreamReader(
					System.in));
			int reader_num = 1;
			reader_num = Integer.parseInt(input.readLine());

			// Get the identified terminal
			CardTerminal terminal = (CardTerminal) terminals
					.get(reader_num - 1);

			// Establish a connection with the card
			PIVCard card = new PIVCard(terminal.connect("*"));
			System.out.println("Card: " + card);
			System.out.println("Card ATR: "
					+ DataUtil.byteArrayToString(card.getATR().getBytes()));


			/*
			 * Perform a POP test using the certificate for validation
			 */
			// Get the cardAuth Certificate
			PIVCertificate pivAuthPC = null;
			PIVCertificate cardAuthPC = null;
			PIVCertificate digSigPC = null;
			PIVCertificate keyEncPC = null;

			try {
				pivAuthPC = card.getPIVAuthCert();
				cardAuthPC = card.getCardAuthCert();
				digSigPC = card.getDigSigCert();
				keyEncPC = card.getKeyEnciphermentCert();
			} catch (NullPointerException e) {
				pivAuthPC = null;
				cardAuthPC = null;
				digSigPC = null;
				keyEncPC = null;
			}

			if (pivAuthPC != null) {
				X509Certificate pivAuth = pivAuthPC.getCertificate();
				System.out.println("### PIV Authentication Certificate ###");
				System.out.println(pivAuth.toString());
			} else {
				System.out.println("### PIV Authentication Certificate ###");
				System.out.println("NO PIV Authentication Certificate!");
			}
			if (cardAuthPC != null) {
				X509Certificate cardAuth = cardAuthPC.getCertificate();
				System.out.println("### Card Authentication Certificate ###");
				System.out.println(cardAuth.toString());
			} else {
				System.out.println("### Card Authentication Certificate ###");
				System.out.println("NO Card Authentication Certificate!");
			}
			if (digSigPC != null) {
				X509Certificate digSig = digSigPC.getCertificate();
				System.out.println("### Digital Signature Certificate ###");
				System.out.println(digSig.toString());
			} else {
				System.out.println("### Digital Signature Certificate ###");
				System.out.println("NO Digital Signature Certificate!");
			}
			if (keyEncPC != null) {
				X509Certificate keyEnc = keyEncPC.getCertificate();
				System.out.println("### Key Encipherment Certificate ###");
				System.out.println(keyEnc.toString());
			} else {
				System.out.println("### Key Encipherment Certificate ###");
				System.out.println("NO Key Encipherment Certificate!");
			}

			// Disconnect
			card.disconnect(false);

		} catch (Throwable e) {
			e.printStackTrace();
		}
	}
}
