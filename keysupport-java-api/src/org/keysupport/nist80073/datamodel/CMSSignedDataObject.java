/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 *
 * $Id: CMSSignedDataObject.java 20 2013-12-16 22:47:05Z grandamp@gmail.com $
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
 * @version $Revision: 20 $
 * Last changed: $LastChangedDate: 2013-12-16 15:47:05 -0700 (Mon, 16 Dec 2013) $
 *****************************************************************************/

package org.keysupport.nist80073.datamodel;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.CON_SPEC;
import org.keysupport.asn1.SET;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.Tag;
import org.keysupport.encoding.der.CMSObjectIdentifiers;
import org.keysupport.encoding.der.ObjectIdentifier;
import org.keysupport.encoding.der.structures.AlgorithmIdentifier;
import org.keysupport.encoding.der.structures.Attribute;
import org.keysupport.encoding.der.structures.CMSSignedData;
import org.keysupport.encoding.der.structures.CMSVersion;
import org.keysupport.encoding.der.structures.CertificateChoices;
import org.keysupport.encoding.der.structures.EncapsulatedContentInfo;
import org.keysupport.encoding.der.structures.IssuerAndSerialNumber;
import org.keysupport.encoding.der.structures.SignedData;
import org.keysupport.encoding.der.structures.SignerInfo;
import org.keysupport.keystore.CertValidator;
import org.keysupport.keystore.CipherEngine;
import org.keysupport.keystore.DigestEngine;
import org.keysupport.util.DataUtil;

/**
 * This class is for validating and generating CMS Signed Data objects defined
 * in FIPS-201
 * <p>
 * Implementation example to be re-written
 *
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 20 $
 */

public class CMSSignedDataObject {

	/**
	 * Field debug. (value is false)
	 */
	private static final boolean debug = false;
	/**
	 * Field signatureObject.
	 */
	private byte[] signatureObject;
	/**
	 * Field signedData.
	 */
	private byte[] signedData;
	/**
	 * Field signer.
	 */
	private X509Certificate signer = null;
	/**
	 * Field signingKey.
	 */
	private PrivateKey signingKey = null;
	/**
	 * Field signedAttrs.
	 */
	private byte[] signedAttrs;
	/**
	 * Field sigToVerify.
	 */
	private byte[] sigToVerify;
	/**
	 * Field sigAlgName.
	 */
	private String sigAlgName = null;
	/**
	 * Field signature.
	 */
	private Signature signature;
	/**
	 * Field provider.
	 */
	private String provider = null;

	/*
	 * Rule based booleans for signature validation
	 */
	/**
	 * Field digestMatch.
	 */
	private boolean digestMatch = false;
	/**
	 * Field usSigAlg.
	 */
	private boolean usSigAlg = false;

	/*
	 * Intended for CHUID Sig
	 */
	/**
	 * Constructor for CMSSignedDataObject.
	 *
	 * @param signatureObject
	 *            byte[]
	 * @param signedData
	 *            byte[]
	 * @throws SignatureException
	 */
	public CMSSignedDataObject(byte[] signatureObject, byte[] signedData)
			throws SignatureException {
		this.setSignatureObject(signatureObject);
		this.setSignedData(signedData);
		this.init();
	}

	/*
	 * Intended for other PIV sigs (SecurityObject & Bio)
	 */
	/**
	 * Constructor for CMSSignedDataObject.
	 *
	 * @param signatureObject
	 *            byte[]
	 * @param signedData
	 *            byte[]
	 * @param signerCert
	 *            X509Certificate
	 *
	 * @throws SignatureException
	 */
	public CMSSignedDataObject(byte[] signatureObject, byte[] signedData,
			X509Certificate signerCert) throws SignatureException {
		this.setSigner(signerCert);
		this.setSignatureObject(signatureObject);
		this.setSignedData(signedData);
		this.init();
	}

	/*
	 * Intended to generate a new signed object
	 */
	/**
	 * Constructor for CMSSignedDataObject.
	 *
	 * @param signedData
	 *            byte[]
	 * @param signerCert
	 *            X509Certificate
	 * @param signingKey
	 *            PrivateKey
	 *
	 * @throws SignatureException
	 */
	public CMSSignedDataObject(byte[] signedData, X509Certificate signerCert,
			PrivateKey signingKey) throws SignatureException {
		this.setSigner(signerCert);
		this.setSignedData(signedData);
		this.signingKey = signingKey;
	}

	/**
	 * Method getSignatureObject.
	 *
	 *
	 * @return byte[]
	 */
	public byte[] getSignatureObject() {
		return this.signatureObject;
	}

	/**
	 * Method getSignedData.
	 *
	 *
	 * @return byte[]
	 */
	public byte[] getSignedData() {
		return this.signedData;
	}

	/**
	 * Method getSigner.
	 *
	 *
	 * @return X509Certificate
	 */
	public X509Certificate getSigner() {
		return this.signer;
	}

	/**
	 * Method init.
	 *
	 *
	 * @throws SignatureException
	 */
	private void init() throws SignatureException {
		try {
			byte[] digest = null;

			CMSSignedData sig = new CMSSignedData(this.signatureObject);
			if (debug) {
				System.out.println("ContentType:\n"
						+ sig.getContentType().toString());
				System.out.println("Decoding SignedData Content");
			}

			SignedData signed_data = sig.getSignedData();
			CMSVersion version = signed_data.getVersion();

			if (debug) {
				System.out.println("CMSVersion:\n" + version.toString());
			}

			AlgorithmIdentifier dai = signed_data.getDigestAlgIDs();
			if (debug) {
				System.out.println("DigestAlgorithmIdentifiers:\n"
						+ dai.toString());
			}

			EncapsulatedContentInfo eci = signed_data.getEncapContentInfo();
			if (debug) {
				System.out.println("EncapsulatedContentInfo:\n"
						+ eci.toString());
			}

			Enumeration<CertificateChoices> certificateset = signed_data
					.getCertificateSet();
			CertificateChoices choice = null;
			if (certificateset.hasMoreElements()) {
				choice = certificateset.nextElement();
			}
			X509Certificate signer = choice.getCertificate();
			if (debug) {
				System.out
						.println("CertificateSet:\nCertificateChoices:\nSigner Certificate:\n"
								+ signer.toString());
			}

			if (!this.signerIsSet()) {
				this.setSigner(signer);
			}

			Enumeration<SignerInfo> signerinfos = signed_data.getSignerInfos();
			SignerInfo si = null;
			if (signerinfos.hasMoreElements()) {
				si = signerinfos.nextElement();
			}
			if (debug) {
				System.out.println("Decoding SignerInfo Content");
			}
			CMSVersion siversion = si.getVersion();
			if (debug) {
				System.out.println("SignerInfo CMSVersion:\n"
						+ siversion.toString());
			}

			IssuerAndSerialNumber iasn = si.getSignerIdentifier();
			if (debug) {
				System.out.println("Signer Name:\n"
						+ iasn.getIssuerName().toString());
				System.out.println("Signer Serial:\n"
						+ DataUtil.byteArrayToString(iasn.getIssuerSerial()
								.toByteArray()));
			}

			AlgorithmIdentifier dalgid = si.getDigestAlgID();
			if (debug) {
				System.out.println("Digest Algorithm:\n" + dalgid.toString());
			}

			/*
			 * Only support SHA-1/SHA-256/SHA-384. Die on validation otherwise.
			 */
			if (dalgid.getAlgOID().equals(CipherEngine.SHA384)) {
				/*
				 * SHA-384
				 */
				digest = DigestEngine.sHA384Sum(this.signedData, this.provider);
			} else if (dalgid.getAlgOID().equals(CipherEngine.SHA256)) {
				/*
				 * SHA-256
				 */
				digest = DigestEngine.sHA256Sum(this.signedData, this.provider);
			} else if (dalgid.getAlgOID().equals(CipherEngine.SHA1)) {
				/*
				 * SHA-1
				 */
				digest = DigestEngine.sHA1Sum(this.signedData, this.provider);
			} else {
				this.usSigAlg = true;
			}

			if (debug) {
				System.out.println("Signed Attributes:");
			}

			if (si.getSignedAttributes() == null) {
				throw new SignatureException(
						"CMS Object does not contain a SignedAttributes!");
			}
			Enumeration<Attribute> sattributes = si.getSignedAttributes();
			byte[] messageDigest = null;

			Attribute sattr = null;
			while (sattributes.hasMoreElements()) {
				sattr = sattributes.nextElement();
				ObjectIdentifier id = sattr.getAttrTypeOID();
				Enumeration<ASN1Object> sattrvals = sattr.getAttributeValues();
				while (sattrvals.hasMoreElements()) {
					ASN1Object sattrval = sattrvals.nextElement();
					if (id.equals(PIVObjectIdentifiers.pivSigner_DN)) {
						/*
						 * X500Principal signerdn = new
						 * X500Principal(sattrval.getBytes());
						 * System.out.println("Attribute Value: " +
						 * DataUtil.byteArrayToString(sattrval.getValue()));
						 */
					} else if (id.equals(CMSObjectIdentifiers.id_messageDigest)) {
						messageDigest = sattrval.getValue();
					} else if (id.equals(CMSObjectIdentifiers.id_contentType)) {
						/*
						 * System.out.println("Attribute Value: " + new
						 * ObjectIdentifier(sattrval.getValue()).toString());
						 */
					} else {
						/*
						 * System.out.println("Attribute Value:\n" +
						 * DataUtil.byteArrayToString(sattrval.getBytes()));
						 */
					}
				}
			}
			if (messageDigest == null) {
				throw new SignatureException(
						"MessageDigest Signed Attribute was null or not in the SignedAttributes!");
			}
			if (Arrays.equals(digest, messageDigest)) {
				if (debug) {
					System.out.println("Matching Digest: "
							+ DataUtil.byteArrayToString(digest));
				}
				this.digestMatch = true;
			} else {
				this.digestMatch = false;
			}
			AlgorithmIdentifier salgid = si.getSigAlgID();
			if (debug) {
				System.out
						.println("Signature Algorithm:\n" + salgid.toString());
				System.out.println("Signature Bytes:\n"
						+ DataUtil.byteArrayToString(si.getSignature()));
			}

			/*
			 * Get the Signed Attributes for Signature Verification
			 */
			if (si.getSignedAttrBytes() != null) {
				this.signedAttrs = si.getSignedAttrBytes();
			} else {
				throw new SignatureException(
						"CMS Object does not contain a SignedAttributes SET in the SignerInfo!");
			}
			if (debug) {
				System.out.println("SignedAttrs to SET:\n"
						+ DataUtil.byteArrayToString(this.signedAttrs));
			}

			/*
			 * May be of assistance to help troubleshoot algorithm issues in a
			 * particular JRE
			 */
			if (debug) {
				System.out
						.println("###############################################################################################");
				System.out.println("List of providers:");
				System.out
						.println("###############################################################################################");
				final Provider[] providers = Security.getProviders();
				for (final Provider p : providers) {
					System.out.format("%s %s%s", p.getName(), p.getVersion(),
							System.getProperty("line.separator"));
					for (final Object o : p.keySet()) {
						System.out.format("\t%s : %s%s", o,
								p.getProperty((String) o),
								System.getProperty("line.separator"));
					}
				}
				System.out
						.println("###############################################################################################");
			}
			this.sigToVerify = si.getSignature();
			this.sigAlgName = CipherEngine.getSigningAlgorithm(
					dalgid.getAlgOID(), salgid.getAlgOID());

		} catch (ASN1Exception e) {
			throw new SignatureException(e);
		} catch (TLVEncodingException e) {
			throw new SignatureException(e);
		}
	}

	/**
	 * Method sign.
	 *
	 *
	 *
	 * @return byte[] * @throws SignatureException
	 */
	public byte[] sign() throws SignatureException {
		try {
			// Digest the Data we are signing
			byte[] digest = DigestEngine.sHA256Sum(this.signedData);

			// Construct the SignedAttribute CON_SPEC

			// adding the contenttype attribute
			Attribute attrct = new Attribute();
			attrct.setAttrTypeOID(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OBJECTID), CMSObjectIdentifiers.id_contentType
					.getEncoded()));
			SET setct = new SET();
			setct.addComponent(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OBJECTID),
					PIVObjectIdentifiers.id_PIV_CHUIDSecurityObject
							.getEncoded()));
			attrct.setAttributeValues(setct);
			if (debug) {
				System.out.println("Content Type: ");
				System.out
						.println(DataUtil.byteArrayToString(attrct.getBytes()));
			}

			// TODO: Add signing time!

			// Adding the message digest attribute
			Attribute attrmd = new Attribute();
			attrmd.setAttrTypeOID(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OBJECTID), CMSObjectIdentifiers.id_messageDigest
					.getEncoded()));
			SET setmd = new SET();
			setmd.addComponent(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OCTETSTRING), digest));
			attrmd.setAttributeValues(setmd);
			if (debug) {
				System.out.println("Message Digest: ");
				System.out
						.println(DataUtil.byteArrayToString(attrmd.getBytes()));
			}

			// Adding the pivSigner_DN Attribute
			Attribute attrsdn = new Attribute();
			attrsdn.setAttrTypeOID(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OBJECTID), PIVObjectIdentifiers.pivSigner_DN
					.getEncoded()));
			SET setsdn = new SET();
			setsdn.addComponent(this.signer.getSubjectX500Principal()
					.getEncoded());
			attrsdn.setAttributeValues(setsdn);
			if (debug) {
				System.out.println("Signer DN: ");
				System.out.println(DataUtil.byteArrayToString(attrsdn
						.getBytes()));
			}

			CON_SPEC signedAttrs = new CON_SPEC(0);
			signedAttrs.addComponent(attrct.getBytes());
			signedAttrs.addComponent(attrmd.getBytes());
			signedAttrs.addComponent(attrsdn.getBytes());
			if (debug) {
				System.out.println("SignedAttributes: ");
				System.out.println(DataUtil.byteArrayToString(signedAttrs
						.getBytes()));
			}

			// Construct the SignerInfo
			SignerInfo si = new SignerInfo();
			// Add the version
			si.setVersion(new CMSVersion(1).getASN1Object());
			// Add info on the Signer
			si.setSignerIdentifier(new IssuerAndSerialNumber(this.signer)
					.getASN1Object());
			// Add the digest algorithm
			si.setDigestAlgID(new AlgorithmIdentifier(CipherEngine.SHA256, null)
					.getASN1Object());
			// Add the signed attributes
			si.setSignedAttributes(signedAttrs);
			// Add the signature algorithm
// RAC changed to ECC
//			si.setSigAlgID(new AlgorithmIdentifier(CipherEngine.RSA, null)
//					.getASN1Object());
			System.out.println("ALGID: ");
            System.out.println(new AlgorithmIdentifier(CipherEngine.SHA256withECDSA, null).getASN1Object().toString());
			si.setSigAlgID(new AlgorithmIdentifier(CipherEngine.SHA256withECDSA, null)
					.getASN1Object());

			// Can't set the sig yet, move on
			// TODO: Move SignerInfo creation to the sign(...) method
            if (null == this.provider) {
				this.signature = Signature
						.getInstance(CipherEngine.getSigningAlgorithm(CipherEngine.SHA256withECDSA));
//								CipherEngine.SHA256withECDSA, CipherEngine.ECDSA));
            }
            /*if (null == this.provider) {
				this.signature = Signature
						.getInstance(CipherEngine.getSigningAlgorithm(
								CipherEngine.SHA256, CipherEngine.RSA));
			} else {
				this.signature = Signature
						.getInstance(CipherEngine.getSigningAlgorithm(
								CipherEngine.SHA256, CipherEngine.RSA), this.provider);
			}
            */
			this.signature.initSign(this.signingKey);
			this.signedAttrs = si.getSignedAttrBytes();
			this.signature.update(this.signedAttrs);
			byte[] sigval = this.signature.sign();
			si.setSignature(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OCTETSTRING), sigval));

			// Add the SignerInfo to the global CMSSignedData
			if (debug) {
				System.out.println("SignerInfo: ");
				System.out.println(DataUtil.byteArrayToString(si.getBytes()));
			}

			SignedData signed_data = new SignedData();
			signed_data.setVersion(new CMSVersion(3).getASN1Object());
			SET setOfdalg = new SET();
			setOfdalg.addComponent(new AlgorithmIdentifier(CipherEngine.SHA256,
					null).getASN1Object());
			signed_data.setDigestAlgIDs(setOfdalg);
			EncapsulatedContentInfo eci = new EncapsulatedContentInfo(
					PIVObjectIdentifiers.id_PIV_CHUIDSecurityObject);
			signed_data.setEncapContentInfo(eci.getASN1Object());
			CON_SPEC csCset = new CON_SPEC(0);
			csCset.addComponent(this.signer.getEncoded());
			signed_data.setCertificateSet(csCset);
			// No CRLS will be added, make sure encoding does not include them
			// if they are null
			SET setOfsi = new SET();
			setOfsi.addComponent(si.getASN1Object());
			signed_data.setSignerInfos(setOfsi);
			if (debug) {
				System.out.println("SignedData: ");
				System.out.println(DataUtil.byteArrayToString(signed_data
						.getBytes()));
			}

			// Construct the CMSSignedData
			// Set the global CMSSignedData object to await the call to
			// sign(...)

			CMSSignedData sig = new CMSSignedData();
			sig.setContentType(ASN1Factory.encodeASN1Object(new Tag(
					Tag.OBJECTID), CMSObjectIdentifiers.id_signedData
					.getEncoded()));
			CON_SPEC signedData = new CON_SPEC(0);
			signedData.addComponent(signed_data.getASN1Object());
			sig.setSignedData(signedData);
			if (debug) {
				System.out.println("Full CMSSignedData: ");
				System.out.println(DataUtil.byteArrayToString(sig.getBytes()));
			}
			return sig.getBytes();

		} catch (Throwable e) {
			throw new SignatureException(e);
		}
	}

	/**
	 * Method setSignatureObject.
	 *
	 * @param signatureObject
	 *            byte[]
	 */
	private void setSignatureObject(byte[] signatureObject) {
		this.signatureObject = signatureObject;
	}

	/**
	 * Method setSignedData.
	 *
	 * @param signedData
	 *            byte[]
	 */
	private void setSignedData(byte[] signedData) {
		this.signedData = signedData;
	}

	/**
	 * Method setSigner.
	 *
	 * @param signerCert
	 *            X509Certificate
	 */
	private void setSigner(X509Certificate signerCert) {
		this.signer = signerCert;
	}

	/**
	 * Method signerIsSet.
	 *
	 *
	 * @return boolean
	 */
	private boolean signerIsSet() {
		return (this.signer != null);
	}

	/**
	 * Method verifySignature.
	 *
	 * @param verifySigner
	 *            boolean
	 *
	 *
	 * @return boolean * @throws SignatureException
	 */
	public boolean verifySignature(boolean verifySigner)
			throws SignatureException {
		boolean verified = false;
		// TODO: Verify rules
		// TODO: Make sure certificate was valid at signing time
        //
		try {
			if (null == this.provider) {
				this.signature = Signature.getInstance(this.sigAlgName);
			} else {
				this.signature = Signature.getInstance(this.sigAlgName, this.provider);
			}
            this.signature = Signature.getInstance(CipherEngine.getSigningAlgorithm(CipherEngine.SHA256withECDSA));

			if (this.signerIsSet()) {
				this.signature.initVerify(this.getSigner());
			} else {
				throw new SignatureException("Signing Certificate was not set!");
			}
			if (this.usSigAlg) {
				throw new SignatureException("Un-Supported Signing Algorithm: "
						+ this.signature.getAlgorithm());
			}
			if (!this.digestMatch) {
				throw new SignatureException(
						"MessageDigest and digest of signature data do not match!");
			}
			this.signature.update(this.signedAttrs);
			if (this.signature.verify(this.sigToVerify)) {
				verified = true;
			} else {
				verified = false;
			}
			if (verified && verifySigner) {
				if (!verifySigner()) {
					verified = false;
					throw new SignatureException(
							"Signature Verified, but certificate is not trusted!.");
				}
			}
		} catch (NoSuchAlgorithmException e) {
			throw new SignatureException(e);
		} catch (InvalidKeyException e) {
			throw new SignatureException(e);
		} catch (NoSuchProviderException e) {
			throw new SignatureException(e);
		}
		return verified;
	}

	/**
	 * Method verifySigner.
	 *
	 *
	 * @return boolean
	 */
	public boolean verifySigner() {
		boolean valid = false;
		// PDVAL logic to validate to Common
		// TODO: Check for EKU value of
		// PIVObjectIdentifiers.id_PIV_content_signing
		try {
			CertValidator pdval = new CertValidator(this.getSigner());
			valid = pdval.validate();
		} catch (Throwable e) {
			e.printStackTrace();
			System.out.println("Certificate validation failed.");
			valid = false;
		}
		return valid;
	}

	/**
	 * Method getProviderName.
	 *
	 * @return String
	 */
	public String getProviderName() {
		return this.provider;
	}

	/**
	 * Method setProviderName.
	 *
	 * @param provider
	 *            String
	 */
	public void setProviderName(String provider) {
		this.provider = provider;
	}
}
