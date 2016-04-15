/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: AsymmetricKeyRefTempl.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.nist80073.cardedge;

import java.io.ByteArrayOutputStream;
import java.util.Enumeration;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class AsymmetricKeyRefTempl {

	// private final static boolean debug = true;

	// private byte templ_type;

	private byte algorithmID;
	private byte[] parameter;

	private byte[] templ;

	/**
	 * Constructor for AsymmetricKeyRefTempl.
	 * @param algorithmID byte
	 * @param parameter byte[]
	 */
	public AsymmetricKeyRefTempl(byte algorithmID, byte[] parameter) {
		this.algorithmID = algorithmID;
		this.parameter = parameter;
		encode();
	}

	/**
	 * Constructor for AsymmetricKeyRefTempl.
	 * @param ba byte[]
	 */
	public AsymmetricKeyRefTempl(byte[] ba) {
		decode(ba);
		this.templ = ba;
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

				switch (child_tag.getBytes()[0]) {

				case Tag.AK_ALGORITHM_ID: {
					this.algorithmID = value[0];
					break;
				}
				case Tag.AK_PARAMETER: {
					this.parameter = value;
					break;
				}
				default: {
					break;
				}
				}
			}
		}

	}

	public void encode() {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			TLV _algorithmID = BERTLVFactory.encodeTLV(new Tag(
					Tag.AK_ALGORITHM_ID), new byte[] { this.algorithmID });
			baos.write(_algorithmID.getBytes());
			TLV _parameter = BERTLVFactory.encodeTLV(new Tag(Tag.AK_PARAMETER),
					this.parameter);
			baos.write(_parameter.getBytes());
			TLV ak_templ = BERTLVFactory.encodeTLV(new Tag(Tag.AK_OBJECT),
					baos.toByteArray());
			this.templ = ak_templ.getBytes();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method getCryptographicMechanism.
	 * @return byte
	 */
	public byte getCryptographicMechanism() {
		return this.algorithmID;
	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		// Reminder: May need to address the overall object tag given use of the
		// single byte[] constructor (from decoding)
		return this.templ;
	}

	/**
	 * Method getParameter.
	 * @return byte[]
	 */
	public byte[] getParameter() {
		return this.parameter;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Asymmetric Key Reference Template:Algorithm ID:\t"
				+ DataUtil.byteToString(this.algorithmID));
		sb.append("\nAsymmetric Key Reference Template:Parameter:\t"
				+ DataUtil.byteArrayToString(this.parameter));
		sb.append('\n');
		return sb.toString();
	}

}