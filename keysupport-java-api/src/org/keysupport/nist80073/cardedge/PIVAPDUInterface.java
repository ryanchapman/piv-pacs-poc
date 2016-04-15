/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVAPDUInterface.java 13 2013-11-07 05:22:58Z grandamp@gmail.com $
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
 * @version $Revision: 13 $
 * Last changed: $LastChangedDate: 2013-11-06 22:22:58 -0700 (Wed, 06 Nov 2013) $
 *****************************************************************************/

package org.keysupport.nist80073.cardedge;

import javax.smartcardio.CommandAPDU;

import org.keysupport.encoding.Tag;

/**
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 13 $
 */
public interface PIVAPDUInterface {

	/*
	 * From 800-73-3 Part 2
	 */
	/**
	 * Field GP_COMMAND.
	 */
	public static final byte GP_COMMAND = (byte) 0x00;
	/**
	 * Field GP_COMMAND_CC.
	 */
	public static final byte GP_COMMAND_CC = (byte) 0x10;
	/**
	 * Field GP_SELECT.
	 */
	public static final byte GP_SELECT = (byte) 0xa4;
	/**
	 * Field PIV_AID.
	 */
	public static final byte[] PIV_AID = { (byte) 0xa0, (byte) 0x00,
			(byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00, (byte) 0x00,
			(byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00 };
	/**
	 * Field PIV_SELECT_HEADER.
	 */
	public static final byte[] PIV_SELECT_HEADER = { GP_COMMAND, (byte) 0xa4,
			(byte) 0x04, (byte) 0x00 };
	/**
	 * Field SELECT_PIV.
	 */
	public static final byte[] SELECT_PIV = { GP_COMMAND, GP_SELECT,
			(byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0xa0, (byte) 0x00,
			(byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00, (byte) 0x00,
			(byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00 };
	/**
	 * Field PIV_GET_DATA_HEADER.
	 */
	public static final byte[] PIV_GET_DATA_HEADER = { GP_COMMAND, (byte) 0xcb,
			(byte) 0x3f, (byte) 0xff };
	/**
	 * Field PIV_VERIFY_HEADER.
	 */
	public static final byte[] PIV_VERIFY_HEADER = { GP_COMMAND, (byte) 0x20,
			(byte) 0x00 };
	/**
	 * Field PIV_CNG_REF_DATA_HEADER.
	 */
	public static final byte[] PIV_CNG_REF_DATA_HEADER = { GP_COMMAND,
			(byte) 0x24, (byte) 0x00 };
	/**
	 * Field PIV_RST_RETRY_CNT_HEADER.
	 */
	public static final byte[] PIV_RST_RETRY_CNT_HEADER = { GP_COMMAND,
			(byte) 0x2c, (byte) 0x00 };
	/**
	 * Field PIV_GEN_AUTH_HEADER.
	 */
	public static final byte[] PIV_GEN_AUTH_HEADER = { GP_COMMAND, (byte) 0x87 };
	/**
	 * Field PIV_GEN_AUTH_CC_HEADER.
	 */
	public static final byte[] PIV_GEN_AUTH_CC_HEADER = { GP_COMMAND_CC,
			(byte) 0x87 };
	/**
	 * Field PIV_PUT_DATA_HEADER.
	 */
	public static final byte[] PIV_PUT_DATA_HEADER = { GP_COMMAND, (byte) 0xdb,
			(byte) 0x3f, (byte) 0xff };
	/**
	 * Field PIV_PUT_DATA_CC_HEADER.
	 */
	public static final byte[] PIV_PUT_DATA_CC_HEADER = { GP_COMMAND_CC,
			(byte) 0xdb, (byte) 0x3f, (byte) 0xff };
	/**
	 * Field PIV_GEN_ASYM_KP_HEADER.
	 */
	public static final byte[] PIV_GEN_ASYM_KP_HEADER = { GP_COMMAND,
			(byte) 0x47, (byte) 0x00 };
	/**
	 * Field PIV_GEN_ASYM_KP_CC_HEADER.
	 */
	public static final byte[] PIV_GEN_ASYM_KP_CC_HEADER = { GP_COMMAND_CC,
			(byte) 0x47, (byte) 0x00 };

	/**
	 * Field PIV_SW_SECURITY_CONDITION_NOT_SATISFIED.
	 */
	public static final int PIV_SW_SECURITY_CONDITION_NOT_SATISFIED = 0x6982;
	/**
	 * Field PIV_SW_AUTHENTICATION_METHOD_BLOCKED.
	 */
	public static final int PIV_SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
	/**
	 * Field PIV_SW_INCORRECT_PARAMETER.
	 */
	public static final int PIV_SW_INCORRECT_PARAMETER = 0x6a80;
	/**
	 * Field PIV_SW_FUNCTION_NOT_SUPPORTED.
	 */
	public static final int PIV_SW_FUNCTION_NOT_SUPPORTED = 0x6a61;
	/**
	 * Field PIV_SW_OBJECT_OR_APPLICATION_NOT_FOUND.
	 */
	public static final int PIV_SW_OBJECT_OR_APPLICATION_NOT_FOUND = 0x6a82;
	/**
	 * Field PIV_SW_NOT_ENOUGH_MEMORY.
	 */
	public static final int PIV_SW_NOT_ENOUGH_MEMORY = 0x6a84;
	/**
	 * Field PIV_SW_INCORRECT_PARAMETER_P1_P2.
	 */
	public static final int PIV_SW_INCORRECT_PARAMETER_P1_P2 = 0x6a86;
	/**
	 * Field PIV_SW_REFERENCE_DATA_NOT_FOUND.
	 */
	public static final int PIV_SW_REFERENCE_DATA_NOT_FOUND = 0x6a88;
	/**
	 * Field PIV_SW_SUCCESSFUL_EXECUTION.
	 */
	public static final int PIV_SW_SUCCESSFUL_EXECUTION = 0x9000;

	/*
	 * 800-73 Defined Tags
	 */

	/**
	 * Method getPIVData.
	 * 
	 * @param pivObjectTag
	 *            Tag
	 * @return CommandAPDU
	 */
	public CommandAPDU getPIVData(Tag pivObjectTag);

	/**
	 * Method selectPIVApplication.
	 * 
	 * @return CommandAPDU
	 */
	public CommandAPDU selectPIVApplication();

}