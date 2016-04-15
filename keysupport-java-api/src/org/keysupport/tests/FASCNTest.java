package org.keysupport.tests;
/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: FASCNTest.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

import org.keysupport.nist80073.datamodel.FASCN;

import org.keysupport.util.DataUtil;

/**
 */
public class FASCNTest {

/*****************************************************************************
 *

 * @param args String[]
 ****************************************************************************/

	public static void main(String args[]) {
		try {

			String agencyCode = "0000";
			String systemCode = "0000";
			String credentialNumber = "000000";
			String credentialSeries = "0";
			String individualCredentialIssue = "0";
			String personIdentifier = "0000000000";
			String organizationalCategory = "0";
			String organizationalIdentifier = "0000";
			String associationCategory = "0";
			
			FASCN zero_fascn = new FASCN(agencyCode, systemCode, credentialNumber, credentialSeries, individualCredentialIssue, personIdentifier, organizationalCategory, organizationalIdentifier, associationCategory);
			System.out.println(zero_fascn.toString());
			System.out.println("Hex Value: " + DataUtil.byteArrayToString(zero_fascn.toByteArray()));
			
		}catch(Throwable e) {
			e.printStackTrace();
		}
	}

}
