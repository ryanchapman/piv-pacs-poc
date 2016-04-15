/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CardBlockedException.java 18 2013-12-16 22:30:01Z grandamp@gmail.com $
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
 * @version $Revision: 18 $
 * Last changed: $LastChangedDate: 2013-12-16 15:30:01 -0700 (Mon, 16 Dec 2013) $
 *****************************************************************************/

package org.keysupport.nist80073;

import javax.smartcardio.CardException;

/**
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 18 $
 */
public class CardBlockedException extends CardException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2275025611999737291L;

	/**
	 * @param message
	 */
	public CardBlockedException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public CardBlockedException(Throwable cause) {
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public CardBlockedException(String message, Throwable cause) {
		super(message, cause);
	}

}
