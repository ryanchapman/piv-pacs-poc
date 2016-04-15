/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: BERTLVFactory.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.encoding;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Vector;

import org.keysupport.util.DataUtil;

/**
 * @author tejohnson
 * 
 * @version $Revision: 3 $
 */
public class BERTLVFactory {

	private final static boolean debug = false;

	/**
	 * @param TLV
	
	 * @return Enumeration<TLV> An enumeration of TLV objects. */
	public static Enumeration<TLV> decodeTLV(byte[] TLV) {

		if (debug) {
			System.out.println("TLV BYTES LENGTH: " + TLV.length);
		}
		int index = 0;
		Vector<TLV> tlvs = new Vector<TLV>();

		while (index < TLV.length) {
			byte[] tag = null;
			int length = 0;
			byte[] value = null;
			byte[] full_tlv = null;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			int start_index = index;

			// Parse the tag
			if (debug) {
				System.out.println("TAG-START");
			}
			if ((byte) (TLV[index] & (byte) 0x1f) == (byte) 0x1f) {
				baos.write(TLV[index]);
				index++;
				while ((byte) (TLV[index] & (byte) 0x80) == (byte) 0x80) {
					if (debug) {
						System.out.println("TAG-PENDING");
					}
					baos.write(TLV[index]);
					index++;
				}
				if ((byte) (TLV[index] & (byte) 0x80) != (byte) 0x80) {
					baos.write(TLV[index]);
					index++;
				}
			} else {
				baos.write(TLV[index]);
				index++;
			}
			if (debug) {
				System.out.println("TAG-DONE");
			}
			tag = baos.toByteArray();
			if (debug) {
				System.out.println("Tag: " + DataUtil.byteArrayToString(tag));
			}
			baos.reset();

			// We need to eval the Tag object up front and prep for a new TLV
			// object
			// Check for indefinite length encoding, assuming the index has been
			// increased beyond the tag value
			if ((new Tag(tag).isConstructed()) && (TLV[index] == (byte) 0x80)) {
				// Replace length and value decoding with the following logic
				if (debug) {
					System.out.println("TAG: "
							+ DataUtil.byteArrayToString(tag));
					System.out.println("LEN: "
							+ DataUtil.byteToString(TLV[index]));
					System.out.println("index: " + index);
					System.out.println("TLV: "
							+ DataUtil.byteArrayToString(TLV));
				}
				// Increase index by one to mark the beginning of the value
				index++;
				int eIndex = (TLV.length - 1);
				boolean EOC = false;
				while (!EOC) {
					// Work our way back looking for EOC
					if (TLV[eIndex] == (byte) 0x00) {
						eIndex--;
						if (TLV[eIndex] == (byte) 0x00) {
							// eIndex--;
							EOC = true;
							break;
						}
					} else {
						eIndex--;
					}
				}
				// At this point index and eIndex mark the "Value"
				TLV current_tlv = encodeTLV(new Tag(tag),
						Arrays.copyOfRange(TLV, index, eIndex));
				// Set the index to eIndex + 2 and, discard what we just
				// witnessed, and continue normal course
				// add new TLV to the Vector
				if (debug) {
					System.out.println("-----Begin Decoded TLV-----");
					System.out.println(current_tlv.toString());
					System.out.println("------End Decoded TLV------");
				}
				tlvs.add(current_tlv);
				index = eIndex + 2;
				if (debug) {
					System.out.println("I-L Decoding Done: TLV.length = "
							+ TLV.length + " - index = " + index);
				}
				// original logic, but make sure we have not reached the end of
				// the array
			} else if (index < TLV.length) {
				// Parse the length
				if (debug) {
					System.out.println("LENGTH-START");
				}
				if ((byte) (TLV[index] & (byte) 0x80) == (byte) 0x80) {
					int len = TLV[index] ^ (byte) 0x80;
					if (debug) {
						System.out.println("Length is " + len + " bytes long.");
					}
					for (int i = 1; i <= len; i++) {
						if (debug) {
							System.out.println("LENGTH-PENDING");
						}
						index++;
						if (debug) {
							System.out.println("Adding Byte to LENGTH value: "
									+ DataUtil.byteToString(TLV[index]));
						}
						baos.write(TLV[index]);
					}
					index++;
				} else {
					if (debug) {
						System.out.println("Length is one 1 long.");
					}
					baos.write(TLV[index]);
					index++;
				}
				if (debug) {
					System.out.println("LENGTH-DONE");
				}
				byte[] encoded_length = baos.toByteArray();
				length = new BigInteger(1, encoded_length).intValue();
				baos.reset();
				if (debug) {
					System.out.println("LEN:" + length);
				}
				int header_len = index - start_index;

				// Parse the value based off of the length
				value = new byte[length];
				System.arraycopy(TLV, index, value, 0, length);
				if (debug) {
					System.out.println("VAL:"
							+ DataUtil.byteArrayToString(value));
				}
				index = index + length;
				int full_tlv_len = header_len + length;
				if (debug) {
					System.out.println("Decoded TLV is " + full_tlv_len
							+ " bytes long.");
				}
				full_tlv = new byte[full_tlv_len];
				System.arraycopy(TLV, start_index, full_tlv, 0, full_tlv_len);
				// Create TLV object
				TLV current_tlv = new TLV(tag, encoded_length, value, full_tlv);
				// add new TLV to the Vector
				if (debug) {
					System.out.println("-----Begin Decoded TLV-----");
					System.out.println(current_tlv.toString());
					System.out.println("------End Decoded TLV------");
				}
				tlvs.add(current_tlv);
			} else {
				// Do nothing
			}
		}
		Enumeration<TLV> tlve = tlvs.elements();
		return tlve;
	}

	// General Warning: Heap size could be reached by encoding large values

	/**
	 * @param tag
	 * @param value
	
	 * @return TLV A fully encoded TLV object. */
	public static TLV encodeTLV(Tag tag, byte[] value) {

		byte[] TLV = null;
		byte[] encoded_length = null;

		try {

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ByteArrayOutputStream lbaos = new ByteArrayOutputStream();

			// Add the Tag
			baos.write(tag.getBytes());

			// Add the encoded Length
			if (value == null) {
				lbaos.write((byte) 0x00);
			} else if (value.length < 0x7f) {
				lbaos.write((byte) value.length);
			} else {
				byte[] input = new byte[] { (byte) (value.length >>> 24),
						(byte) (value.length >> 16 & 0xff),
						(byte) (value.length >> 8 & 0xff),
						(byte) (value.length & 0xff) };
				if (debug) {
					System.out.println(DataUtil.byteArrayToString(input));
				}
				int i = 0;
				while (i < input.length) {
					if (input[i] != (byte) 0x00) {
						break;
					} else {
						i++;
					}
				}
				int index = input.length - i;
				byte[] output = new byte[index];
				System.arraycopy(input, i, output, 0, index);
				lbaos.write((byte) 0x80 | (byte) output.length);
				lbaos.write(output);
			}
			encoded_length = lbaos.toByteArray();
			baos.write(encoded_length);

			// Add the Value if not null
			if (value != null) {
				baos.write(value);
			}

			TLV = baos.toByteArray();
			if (debug) {
				System.out.println(DataUtil.byteArrayToString(TLV));
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return new TLV(tag.getBytes(), encoded_length, value, TLV);

	}

	/**
	 *
	 */
	public BERTLVFactory() {
		// Empty constructor
	}

}