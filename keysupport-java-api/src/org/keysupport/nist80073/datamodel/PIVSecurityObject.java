/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVSecurityObject.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.nist80073.datamodel;

import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVSecurityObject {

	// private final static boolean debug = true;

	private byte[] mapping;
	private byte[] so;
	// private byte[] edc; //EDC is never used, consider removing.

	private byte[] pso;

	public PIVSecurityObject() {

		encode();

	}

	/**
	 * Constructor for PIVSecurityObject.
	 * @param ba byte[]
	 */
	public PIVSecurityObject(byte[] ba) {
		decode(ba);
		this.pso = ba;
	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	public void decode(byte[] ba) {

		Enumeration<?> children = BERTLVFactory.decodeTLV(ba);
		while (children.hasMoreElements()) {

			TLV child_tlv = (TLV) children.nextElement();
			Tag child_tag = child_tlv.getTag();
			byte[] value = child_tlv.getValue();

			switch (child_tag.getBytes()[0]) {

			case Tag.SO_MAPPING: {
				this.mapping = value;
				break;
			}
			case Tag.SO_SO: {
				this.so = value;
				break;
			}
			/*
			 * case Tag.CHUID_ERROR_DETECT_CODE: { this.edc = value; break; }
			 */default: {
				break;
			}
			}
		}

	}

	public void encode() {
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.pso;
	}

	/**
	 * Method getSecurityObject.
	 * @return byte[]
	 */
	public byte[] getSecurityObject() {
		return this.so;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Security Object:Mapping of DG to ContainerID:\t"
				+ DataUtil.byteArrayToString(this.mapping));
		sb.append("\nSecurity Object:Security Object:\t\t"
				+ DataUtil.byteArrayToString(this.so));
		sb.append('\n');
		return sb.toString();
	}

}