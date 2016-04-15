/*
 * Copyright 2005-2006 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 */
/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: ResponseAPDU.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
 * @author  Andreas Sterbenz
 * @author  JSR 268 Expert Group
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 3 $
 * Last changed: $LastChangedDate: 2013-07-23 10:00:13 -0600 (Tue, 23 Jul 2013) $
 *****************************************************************************/

package org.keysupport.smartcardio;

import java.util.Arrays;

/**
 * A response APDU as defined in ISO/IEC 7816-4. It consists of a conditional
 * body and a two byte trailer.
 * This class does not attempt to verify that the APDU encodes a semantically
 * valid response.
 *
 * <p>Instances of this class are immutable. Where data is passed in or out
 * via byte arrays, defensive cloning is performed.
 *
 * @see CommandAPDU
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 * @author  JSR 268 Expert Group
 */
public final class ResponseAPDU implements java.io.Serializable {

    private static final long serialVersionUID = 6962744978375594225L;

    /** @serial */
    private byte[] apdu;
    
/* Consider the following status words
 * 
    short SW_NO_ERROR		      = (short)0x9000;
    short SW_BYTES_REMAINING_00 = 0x6100;
    short SW_WRONG_LENGTH	      = 0x6700;
    short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    short SW_FILE_INVALID       = 0x6983;
    short SW_DATA_INVALID	      = 0x6984;
    short SW_CONDITIONS_NOT_SATISFIED	      = 0x6985;
    short SW_COMMAND_NOT_ALLOWED	      = 0x6986;
    short SW_APPLET_SELECT_FAILED	      = 0x6999;
    short SW_WRONG_DATA	      = 0x6A80;
    short SW_FUNC_NOT_SUPPORTED = 0x6A81;
    short SW_FILE_NOT_FOUND     = 0x6A82;
    short SW_RECORD_NOT_FOUND   = 0x6A83;
    short SW_INCORRECT_P1P2 	  = 0x6A86;
    short SW_WRONG_P1P2 	      = 0x6B00;
    short SW_CORRECT_LENGTH_00  = 0x6C00;
    short SW_INS_NOT_SUPPORTED  = 0x6D00;
    short SW_CLA_NOT_SUPPORTED  = 0x6E00;
    short SW_UNKNOWN            = 0x6F00;
    short SW_FILE_FULL = 0x6A84;
*/    

    /** Status Words **/
    public static final byte[] SW_NO_ERROR = { (byte)0x90, (byte)0x00 };
    public static final byte[] SW_BYTES_REMAINING  = { (byte)0x61, (byte)0x00 };
    public static final byte[] SW_WRONG_LENGTH  = { (byte)0x67, (byte)0x00 };
    public static final byte[] SW_SECURITY_STATUS_NOT_SATISFIED  = { (byte)0x69, (byte)0x82 };
    public static final byte[] SW_FILE_INVALID  = { (byte)0x69, (byte)0x83 };
    public static final byte[] SW_DATA_INVALID  = { (byte)0x69, (byte)0x84 };
    public static final byte[] SW_CONDITIONS_NOT_SATISFIED  = { (byte)0x69, (byte)0x85 };
    public static final byte[] SW_COMMAND_NOT_ALLOWED  = { (byte)0x69, (byte)0x86 };
    public static final byte[] SW_APPLET_SELECT_FAILED  = { (byte)0x69, (byte)0x99 };
    public static final byte[] SW_WRONG_DATA  = { (byte)0x6a, (byte)0x80 };
    public static final byte[] SW_FUNC_NOT_SUPPORTED  = { (byte)0x6a, (byte)0x81 };
    public static final byte[] SW_FILE_NOT_FOUND = { (byte)0x6a, (byte)0x82 };
    public static final byte[] SW_RECORD_NOT_FOUND = { (byte)0x6a, (byte)0x83 };
    public static final byte[] SW_FILE_FULL = { (byte)0x6a, (byte)0x84 };
    public static final byte[] SW_INCORRECT_P1P2 = { (byte)0x6a, (byte)0x86 };
    public static final byte[] SW_WRONG_P1P2 = { (byte)0x6b, (byte)0x00 };
    public static final byte[] SW_CORRECT_LENGTH_00 = { (byte)0x6c, (byte)0x00 };
    public static final byte[] SW_INS_NOT_SUPPORTED = { (byte)0x6d, (byte)0x00 };
    public static final byte[] SW_CLA_NOT_SUPPORTED = { (byte)0x6e, (byte)0x00 };
    public static final byte[] SW_UNKNOWN = { (byte)0x6F, (byte)0x00 };
    
    /**
     * Constructs a ResponseAPDU from a byte array containing the complete
     * APDU contents (conditional body and trailed).
     *
     * <p>Note that the byte array is cloned to protect against subsequent
     * modification.
     *
     * @param apdu_bytes the complete response APDU
     *
     * @throws NullPointerException if apdu is null
     * @throws IllegalArgumentException if apdu.length is less than 2
     */
    public ResponseAPDU(byte[] apdu_bytes) {
    	byte[] _apdu = apdu_bytes.clone();
        check(_apdu);
        this.apdu = _apdu;
    }
    
    public ResponseAPDU(byte[] apdu_bytes, byte[] sw) {
    	byte[] _apdu = apdu_bytes.clone();
        check(_apdu);
        this.apdu = _apdu;
    }

    private static void check(byte[] apdu) {
        if (apdu.length < 2) {
            throw new IllegalArgumentException("apdu must be at least 2 bytes long");
        }
    }

    /**
     * Returns the number of data bytes in the response body (Nr) or 0 if this
     * APDU has no body. This call is equivalent to
     * <code>getData().length</code>.
     *
     * @return the number of data bytes in the response body or 0 if this APDU
     * has no body.
     */
    public int getNr() {
        return this.apdu.length - 2;
    }

    /**
     * Returns a copy of the data bytes in the response body. If this APDU as
     * no body, this method returns a byte array with a length of zero.
     *
     * @return a copy of the data bytes in the response body or the empty
     *    byte array if this APDU has no body.
     */
    public byte[] getData() {
        byte[] data = new byte[this.apdu.length - 2];
        System.arraycopy(this.apdu, 0, data, 0, data.length);
        return data;
    }

    /**
     * Returns the value of the status byte SW1 as a value between 0 and 255.
     *
     * @return the value of the status byte SW1 as a value between 0 and 255.
     */
    public int getSW1() {
        return this.apdu[this.apdu.length - 2] & 0xff;
    }

    /**
     * Returns the value of the status byte SW2 as a value between 0 and 255.
     *
     * @return the value of the status byte SW2 as a value between 0 and 255.
     */
    public int getSW2() {
        return this.apdu[this.apdu.length - 1] & 0xff;
    }

    /**
     * Returns the value of the status bytes SW1 and SW2 as a single
     * status word SW.
     * It is defined as
     * <code>(getSW1() << 8) | getSW2()</code>.
     *
     * @return the value of the status word SW.
     */
    public int getSW() {
        return (getSW1() << 8) | getSW2();
    }

    /**
     * Sets the value of SW1 and SW2 as a single status word SW.
     */
    public void setSW(byte[] sw) {
    	byte[] newapdu = new byte[this.apdu.length + 2];
    	System.arraycopy(this.apdu, 0, newapdu, 0, this.apdu.length);
    	System.arraycopy(sw, 0, newapdu, newapdu.length-2, sw.length);
    	this.apdu = newapdu;
    }

    /**
     * Returns a copy of the bytes in this APDU.
     *
     * @return a copy of the bytes in this APDU.
     */
    public byte[] getBytes() {
        return this.apdu.clone();
    }

    /**
     * Returns a string representation of this response APDU.
     *
     * @return a String representation of this response APDU.
     */
    public String toString() {
        return "ResponseAPDU: " + this.apdu.length + " bytes, SW="
            + Integer.toHexString(getSW());
    }

    /**
     * Compares the specified object with this response APDU for equality.
     * Returns true if the given object is also a ResponseAPDU and its bytes are
     * identical to the bytes in this ResponseAPDU.
     *
     * @param obj the object to be compared for equality with this response APDU
     * @return true if the specified object is equal to this response APDU
     */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ResponseAPDU)) {
            return false;
        }
        ResponseAPDU other = (ResponseAPDU)obj;
        return Arrays.equals(this.apdu, other.apdu);
    }

    /**
     * Returns the hash code value for this response APDU.
     *
     * @return the hash code value for this response APDU.
     */
    public int hashCode() {
        return Arrays.hashCode(this.apdu);
    }

    private void readObject(java.io.ObjectInputStream in)
            throws java.io.IOException, ClassNotFoundException {
        this.apdu = (byte[])in.readUnshared();
        check(this.apdu);
    }

}