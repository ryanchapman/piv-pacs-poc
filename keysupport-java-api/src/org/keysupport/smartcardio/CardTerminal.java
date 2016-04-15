/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CardTerminal.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.smartcardio;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

import org.keysupport.nist80073.PIVCard;

/**
 */
public class CardTerminal {

	private Object terminal;

	// On a desktop system, it will return a handle to a
	// javax.smartcardio.Terminal
	// For now, we are simply going to move the code for establishing the
	// connection to here.

	public CardTerminal() {
		try {
			System.setProperty("sun.security.smartcardio.t0GetResponse",
					"false");
			System.setProperty("sun.security.smartcardio.t1GetResponse",
					"false");
			javax.smartcardio.TerminalFactory factory = javax.smartcardio.TerminalFactory
					.getDefault();
			System.out.println("Provider: " + factory.getProvider().getName()
					+ " - " + factory.getProvider().getInfo());
			List<javax.smartcardio.CardTerminal> terminals = factory
					.terminals().list();
			//TODO: Change this class to add methods to return the terminals and provide for terminal selection
			System.out.println("Available Card Readers:\n");
			for (int i = 0; i < terminals.size(); i++) {
				javax.smartcardio.CardTerminal term = terminals
						.get(i);
				int dnum = i + 1;
				System.out.println(dnum + ": " + term.getName());
			}
			System.out
					.println("\nEnter a number of the reader which contains the PIV credential,");
			System.out.print("and then press [Enter]: ");
			BufferedReader input = new BufferedReader(new InputStreamReader(
					System.in));
			int reader_num = 1;
			reader_num = Integer.parseInt(input.readLine());

			// Get the identified terminal
			this.terminal = terminals
					.get(reader_num - 1);

		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	/**
	 * Constructor for CardTerminal.
	 * @param fake boolean
	 */
	public CardTerminal(boolean fake) {
		try {
			System.setProperty("sun.security.smartcardio.t0GetResponse",
					"false");
			System.setProperty("sun.security.smartcardio.t1GetResponse",
					"false");
			javax.smartcardio.TerminalFactory factory = javax.smartcardio.TerminalFactory
					.getDefault();
			List<javax.smartcardio.CardTerminal> terminals = factory
					.terminals().list();
			this.terminal = terminals.get(0);
		} catch (Throwable e) {
			e.printStackTrace();
		}		
	}
	
	
	
	
	// PIVCard for now, could be an abstract Card object later 
	/**
	 * Method getPIVCard.
	 * @return PIVCard
	 * @throws CardTerminalException
	 */
	public PIVCard getPIVCard() throws CardTerminalException {
		try {
			javax.smartcardio.CardTerminal terminal = (javax.smartcardio.CardTerminal) this.terminal;
			return new PIVCard(terminal.connect("*"));
		} catch (Throwable e) {
			throw new CardTerminalException(e);
		}
	}

}
