/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVDiscoveryObject.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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
public class PIVDiscoveryObject {

	// private final static boolean debug = true;

	private byte[] aid;
	private byte[] pin_pol;
	private boolean g_pin_primary = false;
	private boolean gpin_s_acr = false;

	private byte[] pdo;

	/**
	 * Constructor for PIVDiscoveryObject.
	 * @param ba byte[]
	 */
	public PIVDiscoveryObject(byte[] ba) {
		decode(ba);
		this.pdo = ba;
	}

	/**
	 * Constructor for PIVDiscoveryObject.
	 * @param aid byte[]
	 * @param pin_pol byte[]
	 */
	public PIVDiscoveryObject(byte[] aid, byte[] pin_pol) {
		this.aid = aid;
		this.pin_pol = pin_pol;
		encode();

	}

	/**
	 * Method decode.
	 * @param ba byte[]
	 */
	public void decode(byte[] ba) {

		Enumeration<TLV> tlvs = BERTLVFactory.decodeTLV(ba);
		while (tlvs.hasMoreElements()) {
			TLV current_tlv = tlvs.nextElement();

			Enumeration<TLV> children = BERTLVFactory.decodeTLV(current_tlv
					.getValue());

			while (children.hasMoreElements()) {

				TLV child_tlv = children.nextElement();
				Tag child_tag = child_tlv.getTag();
				byte[] value = child_tlv.getValue();

				if (child_tag.equals(Tag.PIV_APP_AID)) {
					this.aid = value;
				} else if (child_tag.equals(Tag.PIV_PIN_POLICY)) {
					this.pin_pol = value;

					// the pin policy is encoded in 2 bytes
					if ((byte) (this.pin_pol[0] & (byte) 0x60) == (byte) 0x60) {
						this.gpin_s_acr = true;
						if ((byte) (this.pin_pol[1] & (byte) 0x10) == (byte) 0x10) {
						} else if ((byte) (this.pin_pol[1] & (byte) 0x20) == (byte) 0x20) {
							this.g_pin_primary = true;
						}
					}
				}
			}
		}
	}

	public void encode() {
	}

	/**
	 * Method getAID.
	 * @return byte[]
	 */
	public byte[] getAID() {
		return this.aid;
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.pdo;
	}

	/**
	 * Method getPINPolicy.
	 * @return byte[]
	 */
	public byte[] getPINPolicy() {
		return this.pin_pol;
	}

	/**
	 * Method globalPINPrimary.
	 * @return boolean
	 */
	public boolean globalPINPrimary() {
		return this.g_pin_primary;
	}

	/**
	 * Method globalPINSatisfiesACR.
	 * @return boolean
	 */
	public boolean globalPINSatisfiesACR() {
		return this.gpin_s_acr;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("PIV Discovery Object:AID:\t\t"
				+ DataUtil.byteArrayToString(this.getAID()));
		sb.append("\nPIV Discovery Object:PIN Policy:\t"
				+ DataUtil.byteArrayToString(this.getPINPolicy()));
		sb.append("\nPIV Discovery Object:Global PIN:\t");
		sb.append("The ");
		if (globalPINPrimary()) {
			sb.append("Global ");
		} else {
			sb.append("Application ");
		}
		sb.append("PIN is primary.");
		sb.append('\n');
		return sb.toString();
	}
}