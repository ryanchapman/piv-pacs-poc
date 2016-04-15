/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: PIVCertificate.java 26 2014-07-08 17:03:16Z grandamp@gmail.com $
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
 * @version $Revision: 26 $
 * Last changed: $LastChangedDate: 2014-07-08 11:03:16 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.nist80073.datamodel;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 */
public class PIVCertificate {

	// private final static boolean debug = true;

	public static byte CERTINFO_GZIP_COMPRESSION = (byte) 0x01;
	private boolean gzip_compressed = false;

	private byte[] certificate;
	private byte[] certinfo;
	private byte[] mscuid;
	private byte[] edc;

	private byte[] piv_cert_obj;

	/**
	 * Constructor for PIVCertificate.
	 * @param ba byte[]
	 */
	public PIVCertificate(byte[] ba) {
		decode(ba);
		this.piv_cert_obj = ba;
	}

	/**
	 * Constructor for PIVCertificate.
	 * 
	 * @param certificate byte[]
	 * @param mscuid byte[]
	 */
	public PIVCertificate(byte[] certificate, byte[] mscuid) {
		this.certificate = certificate;
		//If the certificate exceeds 1856 bytes, then it must be compressed
		if (certificate.length >= 1856) {
			this.gzip_compressed = true;
			this.certinfo = new byte[] { CERTINFO_GZIP_COMPRESSION };
			System.out.println("CERTIFICATE MUST BE COMPRESSED!");
		} else {
			this.gzip_compressed = false;
			this.certinfo = new byte[] { (byte)0x00 };
		}
		this.mscuid = mscuid;
		encode();
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

			case Tag.PIV_CERT_CERTIFICATE: {
				this.certificate = value;
				break;
			}
			case Tag.PIV_CERT_CERTINFO: {
				this.certinfo = value;
				if ((byte) (this.certinfo[0] & CERTINFO_GZIP_COMPRESSION) == CERTINFO_GZIP_COMPRESSION) {
					this.gzip_compressed = true;
				}
				break;
			}
			case Tag.PIV_CERT_MSCUID: {
				this.mscuid = value;
				break;
			}
			case Tag.ERROR_DETECT_CODE: {
				this.edc = value;
				break;
			}
			default: {
				break;
			}
			}
		}
	}

	public void encode() {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			// Certificate
			if (this.gzip_compressed) {
				//If GZIP, then gzip first
			    ByteArrayOutputStream gzbaos = new ByteArrayOutputStream();
			    GZIPOutputStream gzos = new GZIPOutputStream(gzbaos);
			    gzos.write(this.certificate);
			    gzos.close();
				TLV _gzctlv = BERTLVFactory
						.encodeTLV(new Tag(Tag.PIV_CERT_CERTIFICATE), gzbaos.toByteArray());
				baos.write(_gzctlv.getBytes());
			} else {
				TLV _ctlv = BERTLVFactory
						.encodeTLV(new Tag(Tag.PIV_CERT_CERTIFICATE), this.certificate);
				baos.write(_ctlv.getBytes());
			}
			// CertInfo
			TLV _citlv = BERTLVFactory.encodeTLV(
					new Tag(Tag.PIV_CERT_CERTINFO), this.certinfo);
			baos.write(_citlv.getBytes());
			// MSCUID
			if (this.mscuid != null) {
				TLV _mctlv = BERTLVFactory.encodeTLV(
						new Tag(Tag.PIV_CERT_MSCUID), this.mscuid);
				baos.write(_mctlv.getBytes());
			}
			// Error Detect Code (Tag only, zero length)
			TLV _edctlv = BERTLVFactory.encodeTLV(new Tag(
					Tag.CHUID_ERROR_DETECT_CODE), null);
			baos.write(_edctlv.getBytes());
			this.piv_cert_obj = baos.toByteArray();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method getCertificate.
	 * @return X509Certificate
	 * @throws IOException
	 * @throws CertificateException
	 */
	public X509Certificate getCertificate() throws IOException,
			CertificateException {

		byte[] cert_data = this.certificate;
		// If CertInfo says it is GZIPd, then decompress
		if (this.gzip_compressed) {
			ByteArrayInputStream bais = new ByteArrayInputStream(cert_data);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			GZIPInputStream gzin = new GZIPInputStream(bais);
			for (int c = gzin.read(); c != -1; c = gzin.read()) {
				baos.write(c);
			}
			cert_data = baos.toByteArray();
		}
		// Render us a Certificate
		ByteArrayInputStream is = new ByteArrayInputStream(cert_data);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(is);

	}

	/**
	 * Method getEncoded.
	 * @return byte[]
	 */
	public byte[] getEncoded() {
		return this.piv_cert_obj;
	}

	/**
	 * Method getMSCUID.
	 * @return String
	 */
	public String getMSCUID() {
		return DataUtil.getString(this.mscuid);
	}

	/****************************************************************************************************
	 * <pre>
	 * Reference:  NIST SP 800-73-2, Part 1, Page 19
	 * 
	 *       http://csrc.nist.gov/publications/nistpubs/800-73-2/sp800-73-2_part1-datamodel-final.pdf
	 * 
	 *  The CertInfo byte in certificates identified above shall be encoded as follows:
	 * 
	 *  CertInfo::= BIT STRING {
	 *                          CompressionTypeMsb(0), // 0 = no compression and 1 = gzip compression.
	 *                          CompressionTypeLsb(1), // shall be set to '0' for PIV Applications
	 *                                      IsX509(2), // shall be set to '0' for PIV Applications
	 *                                        RFU3(3),
	 *                                        RFU4(4),
	 *                                        RFU5(5),
	 *                                        RFU6(6),
	 *                                        RFU7(7)
	 *                         }
	 * 
	 * Discussion:  The BIT STRING value can only be 0x00 or 0x80.  Cards produced by ActivID put 0x01.
	 * 
	 * This code can be used to demonstrate the effect of the mistake on the CertInfo BIT STRING.  It
	 * would appear that the ActivID PIV implementations do not encode 0x00 or 0x80 in CertInfo.  It
	 * would also appear that ActivID compresses the certificate on the card since each certificate will
	 * likely exceed the 1856 byte recommended max lengh in 800-73-2, Part 1.  The value that ActivID
	 * places in the CertInfo field is 0x01 (00000001), which translates to RFU7.  Since this field is
	 * (R)eserved for (F)uture (U)se, it would appear that this encoding is in error.
	 * </pre>
	 * 
	 * @return boolean
	 ***************************************************************************************************/

	public boolean isGZIPCompressed() {
		return this.gzip_compressed;
	}

	/**
	 * Method toString.
	 * @return String
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		byte[][] cert_data = DataUtil.getArrays(this.certificate, 50, false);
		for (int i = 0; i < cert_data.length; i++) {
			sb.append("PIV CERTIFICATE:CERTIFICATE:\t"
					+ DataUtil.byteArrayToString(cert_data[i]) + "\n");
		}
		sb.append("PIV CERTIFICATE:CERTINFO:\t");
		if (isGZIPCompressed()) {
			sb.append("Certificate is GZIP Compressed.");
		}
		sb.append("\nPIV CERTIFICATE:MSCUID:\t\t");
		if (this.mscuid != null) {
			sb.append(this.getMSCUID());
		} else {
			sb.append("[null]");
		}
		sb.append("\nPIV CERTIFICATE:EDC:\t");
		if (this.edc != null) {
			sb.append(DataUtil.byteArrayToString(this.edc));
		} else {
			sb.append("[null]");
		}
		sb.append('\n');
		return sb.toString();
	}

}