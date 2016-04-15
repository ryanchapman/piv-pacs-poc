/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: InvalidPinException.java 18 2013-12-16 22:30:01Z grandamp@gmail.com $
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
public class InvalidPinException extends CardException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5784062163826637874L;

	/*
	 * Optional attempts remaining
	 */
	/**
	 * Field remain.
	 */
	private int remain = 0;
	
	/**
	
	 * @return the remain */
	public int getRemainingAttempts() {
		return this.remain;
	}

	/**
	 * Constructor for InvalidPinException.
	 * @param message String
	 */
	public InvalidPinException(String message) {
		super(message);
	}

	/**
	 * Constructor for InvalidPinException.
	 * @param message String
	 * @param attemptRemain int
	 */
	public InvalidPinException(String message, int attemptRemain) {
		super(message + " " + attemptRemain + " attempt(s) remaining before the card is blocked.");
		this.remain = attemptRemain;
	}

	/**
	 * Constructor for InvalidPinException.
	 * @param cause Throwable
	 */
	public InvalidPinException(Throwable cause) {
		super(cause);
	}

	/**
	 * Constructor for InvalidPinException.
	 * @param message String
	 * @param cause Throwable
	 */
	public InvalidPinException(String message, Throwable cause) {
		super(message, cause);
	}

}
