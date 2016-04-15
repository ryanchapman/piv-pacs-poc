/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: TimestampPrintStream.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.util;

import java.io.PrintStream;
import java.util.Calendar;

/**
 */
public final class TimestampPrintStream extends PrintStream {

	private static long start;

	/**
	 * Constructor for TimestampPrintStream.
	 * @param out PrintStream
	 */
	public TimestampPrintStream(PrintStream out) {
		super(out);
		start = Calendar.getInstance().getTimeInMillis();
	}

	@Override
	public void println() {
		timestamp();
		super.println();
	}

	/**
	 * Method println.
	 * @param x boolean
	 */
	@Override
	public void println(boolean x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x char
	 */
	@Override
	public void println(char x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x char[]
	 */
	@Override
	public void println(char x[]) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x double
	 */
	@Override
	public void println(double x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x float
	 */
	@Override
	public void println(float x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x int
	 */
	@Override
	public void println(int x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x long
	 */
	@Override
	public void println(long x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x Object
	 */
	@Override
	public void println(Object x) {
		timestamp();
		super.println(x);
	}

	/**
	 * Method println.
	 * @param x String
	 */
	@Override
	public void println(String x) {
		timestamp();
		super.println(x);
	}

	private void timestamp() {
		long checkpoint = Calendar.getInstance().getTimeInMillis() - start;
		super.print("[DURATION: " + checkpoint + "ms] - ");
	}
}
