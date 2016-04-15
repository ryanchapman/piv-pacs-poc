/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: ASN1ConstructedType.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.asn1;

/**
 */
public interface ASN1ConstructedType extends ASN1UniversalClass {
	/**
	 * Method addComponent.
	 * @param obj ASN1Object
	 * @throws ASN1Exception
	 */
	public void addComponent(ASN1Object obj) throws ASN1Exception;
	/**
	 * Method addComponent.
	 * @param encoded byte[]
	 * @throws ASN1Exception
	 */
	public void addComponent(byte[] encoded) throws ASN1Exception;
}
