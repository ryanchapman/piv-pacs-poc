/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: CertValidator.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
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

package org.keysupport.keystore;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;

import org.keysupport.util.TimestampPrintStream;

/**
 */
public class CertValidator {

	static boolean debug = true;

	// static boolean httpProxy = false;
	static boolean inhibitAnyPolicy = true;
	// static String http_proxy = "";
	// static String http_proxy_port = "";

/*
 * 	public static String COMMON_SHA1_PEM = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIDoTCCAomgAwIBAgIQKTZHquOKrIZKI1byyrdhrzANBgkqhkiG9w0BAQUFADBO\n"
			+ "MQswCQYDVQQGEwJ1czEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQ0wCwYDVQQL\n"
			+ "EwRGQkNBMRYwFAYDVQQDEw1Db21tb24gUG9saWN5MB4XDTA3MTAxNTE1NTgwMFoX\n"
			+ "DTI3MTAxNTE2MDgwMFowTjELMAkGA1UEBhMCdXMxGDAWBgNVBAoTD1UuUy4gR292\n"
			+ "ZXJubWVudDENMAsGA1UECxMERkJDQTEWMBQGA1UEAxMNQ29tbW9uIFBvbGljeTCC\n"
			+ "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJeNvTMn5K1b+3i9L0dHbsd4\n"
			+ "6ZOcpN7JHP0vGzk4rEcXwH53KQA7Ax9oD81Npe53uCxiazH2+nIJfTApBnznfKM9\n"
			+ "hBiKHa4skqgf6F5PjY7rPxr4nApnnbBnTfAu0DDew5SwoM8uCjR/VAnTNr2kSVdS\n"
			+ "c+md/uRIeUYbW40y5KVIZPMiDZKdCBW/YDyD90ciJSKtKXG3d+8XyaK2lF7IMJCk\n"
			+ "FEhcVlcLQUwF1CpMP64Sm1kRdXAHImktLNMxzJJ+zM2kfpRHqpwJCPZLr1LoakCR\n"
			+ "xVW9QLHIbVeGlRfmH3O+Ry4+i0wXubklHKVSFzYIWcBCvgortFZRPBtVyYyQd+sC\n"
			+ "AwEAAaN7MHkwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O\n"
			+ "BBYEFC9Yl9ipBZilVh/72at17wI8NjTHMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJ\n"
			+ "KwYBBAGCNxUCBBYEFHa3YJbdFFYprHWF03BjwbxHhhyLMA0GCSqGSIb3DQEBBQUA\n"
			+ "A4IBAQBgrvNIFkBypgiIybxHLCRLXaCRc+1leJDwZ5B6pb8KrbYq+Zln34PFdx80\n"
			+ "CTj5fp5B4Ehg/uKqXYeI6oj9XEWyyWrafaStsU+/HA2fHprA1RRzOCuKeEBuMPdi\n"
			+ "4c2Z/FFpZ2wR3bgQo2jeJqVW/TZsN5hs++58PGxrcD/3SDcJjwtCga1GRrgLgwb0\n"
			+ "Gzigf0/NC++DiYeXHIowZ9z9VKEDfgHLhUyxCynDvux84T8PCVI8L6eaSP436REG\n"
			+ "WOE2QYrEtr+O3c5Ks7wawM36GpnScZv6z7zyxFSjiDV2zBssRm8MtNHDYXaSdBHq\n"
			+ "S4CNHIkRi+xb/xfJSPzn4AYR4oRe\n" + "-----END CERTIFICATE-----";
*/
	public static String COMMON_SHA2_PEM = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIEYDCCA0igAwIBAgICATAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx\n"
			+ "GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE\n"
			+ "AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEwMTIwMTE2NDUyN1oXDTMw\n"
			+ "MTIwMTE2NDUyN1owWTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu\n"
			+ "bWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UEAxMYRmVkZXJhbCBDb21tb24gUG9s\n"
			+ "aWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2HX7NRY0WkG/\n"
			+ "Wq9cMAQUHK14RLXqJup1YcfNNnn4fNi9KVFmWSHjeavUeL6wLbCh1bI1FiPQzB6+\n"
			+ "Duir3MPJ1hLXp3JoGDG4FyKyPn66CG3G/dFYLGmgA/Aqo/Y/ISU937cyxY4nsyOl\n"
			+ "4FKzXZbpsLjFxZ+7xaBugkC7xScFNknWJidpDDSPzyd6KgqjQV+NHQOGgxXgVcHF\n"
			+ "mCye7Bpy3EjBPvmE0oSCwRvDdDa3ucc2Mnr4MrbQNq4iGDGMUHMhnv6DOzCIJOPp\n"
			+ "wX7e7ZjHH5IQip9bYi+dpLzVhW86/clTpyBLqtsgqyFOHQ1O5piF5asRR12dP8Qj\n"
			+ "wOMUBm7+nQIDAQABo4IBMDCCASwwDwYDVR0TAQH/BAUwAwEB/zCB6QYIKwYBBQUH\n"
			+ "AQsEgdwwgdkwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNh\n"
			+ "L2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCBlQYIKwYBBQUHMAWGgYhsZGFwOi8v\n"
			+ "bGRhcC5mcGtpLmdvdi9jbj1GZWRlcmFsJTIwQ29tbW9uJTIwUG9saWN5JTIwQ0Es\n"
			+ "b3U9RlBLSSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0aWZpY2F0ZTti\n"
			+ "aW5hcnksY3Jvc3NDZXJ0aWZpY2F0ZVBhaXI7YmluYXJ5MA4GA1UdDwEB/wQEAwIB\n"
			+ "BjAdBgNVHQ4EFgQUrQx6dVzl85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQAD\n"
			+ "ggEBAI9z2uF/gLGH9uwsz9GEYx728Yi3mvIRte9UrYpuGDco71wb5O9Qt2wmGCMi\n"
			+ "TR0mRyDpCZzicGJxqxHPkYnos/UqoEfAFMtOQsHdDA4b8Idb7OV316rgVNdF9IU+\n"
			+ "7LQd3nyKf1tNnJaK0KIyn9psMQz4pO9+c+iR3Ah6cFqgr2KBWfgAdKLI3VTKQVZH\n"
			+ "venAT+0g3eOlCd+uKML80cgX2BLHb94u6b2akfI8WpQukSKAiaGMWMyDeiYZdQKl\n"
			+ "Dn0KJnNR6obLB6jI/WNaNZvSr79PMUjBhHDbNXuaGQ/lj/RqDG8z2esccKIN47lQ\n"
			+ "A2EC/0rskqTcLe4qNJMHtyznGI8=\n" + "-----END CERTIFICATE-----";

	private static void init() {
		if (debug) {
			AccessController.doPrivileged(new PrivilegedAction<Void>() {
				@Override
				public Void run() {
					System.setProperty("java.security.debug", "all");
					System.setOut(new TimestampPrintStream(System.err));
					System.setErr(new TimestampPrintStream(System.out));
					return null;
				}
			});

			Properties pr = System.getProperties();
			TreeSet<Object> propKeys = new TreeSet<Object>(pr.keySet());
			for (Iterator<Object> it = propKeys.iterator(); it.hasNext();) {
				String key = (String) it.next();
				System.out.println("" + key + "=" + pr.get(key));
			}
		}

		/*
		 * if (httpProxy) { System.setProperty("http.proxyHost", http_proxy);
		 * System.setProperty("http.proxyPort", http_proxy_port); }
		 */
		System.setProperty("com.sun.security.enableCRLDP", "true");
		Security.setProperty("ocsp.enable", "true");
		System.setProperty("com.sun.security.enableAIAcaIssuers", "true");

	}

	X509Certificate ee;

	/**
	 * Default Constructor
	 * 
	 * @param ee
	 *            InputStream containing the certificate to validate to COMMON.
	
	 * @exception Exception
	 *                Exception thrown if certificate path construction or
	 *                validation fails. */
	public CertValidator(X509Certificate ee) throws Exception {
		init();
		this.ee = ee;
	}

	/**
	 * Method validate.
	 * @return boolean
	 * @throws IOException 
	 */
	public boolean validate() throws IOException {
		boolean valid = false;
		FileOutputStream fvpath = null;
		try {
			init();

			CertificateFactory cf = CertificateFactory.getInstance("X509");
			ByteArrayInputStream bais = new ByteArrayInputStream(
					COMMON_SHA2_PEM.getBytes());
			X509Certificate ta = (X509Certificate) cf.generateCertificate(bais);

			if (debug) {
				if (this.ee.hasUnsupportedCriticalExtension()) {
					System.out
							.println("JAVA THINKS THE EE CERT HAS AN UNSUPPORTED EXTENSION");
					Iterator<String> extensions = this.ee.getCriticalExtensionOIDs()
							.iterator();
					System.out.println("Critical Extension OIDS:");
					while (extensions.hasNext()) {
						System.out.println(extensions.next());
					}
				}
			}

			// X509Certificate ta =
			// (X509Certificate)cf.generateCertificate(tafile);
			if (debug) {
				if (ta.hasUnsupportedCriticalExtension()) {
					System.out
							.println("JAVA THINKS THE TA CERT HAS AN UNSUPPORTED EXTENSION");
					Iterator<String> extensions = ta.getCriticalExtensionOIDs()
							.iterator();
					System.out.println("Critical Extension OIDS:");
					while (extensions.hasNext()) {
						System.out.println(extensions.next());
					}
				}
			}

			X509CertSelector selector = new X509CertSelector();
			selector.setCertificate(this.ee);
			TrustAnchor anchor = new TrustAnchor(ta, null);

			List<Certificate> cert_list = new ArrayList<Certificate>();
			cert_list.add(this.ee);
			cert_list.add(ta);
			CertStoreParameters cparam = new CollectionCertStoreParameters(
					cert_list);
			CertStore cstore = CertStore.getInstance("Collection", cparam,
					"SUN");

			PKIXBuilderParameters params = new PKIXBuilderParameters(
					Collections.singleton(anchor), selector);
			params.setRevocationEnabled(true);
			params.setAnyPolicyInhibited(inhibitAnyPolicy);
			params.setPolicyQualifiersRejected(true);
			// params.setInitialPolicies(Collections.singleton("2.16.840.1.101.3.2.1.3.13"));
			params.addCertStore(cstore);
			if (debug) {
				System.out.println("Parameters:");
				System.out.println(params.toString());
			}

			if (debug) {
				System.out.println("--- BEGIN PATH DISCOVERY ---");
			}
			CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "SUN");

			if (debug) {
				System.out.println("Path Builder Provider: "
						+ cpb.getProvider().toString());
			}

			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb
					.build(params);
			if (debug) {
				System.out.println("Result:");
				System.out.println(result.toString());
			}
			if (debug) {
				System.out.println("--- END PATH DISCOVERY ---");
			}

			CertPath cp = result.getCertPath();
			if (debug) {
				System.out.println("Parameters:");
				System.out.println(params.toString());
			}

			if (debug) {
				System.out.println("--- BEGIN PATH VALIDATION ---");
			}
			CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult pvr = (PKIXCertPathValidatorResult) cpv
					.validate(cp, params);
			if (debug) {
				System.out.println(pvr);
			}
			if (debug) {
				System.out.println("--- END PATH VALIDATION ---");
			}

			// If we got this far, all is good!
			System.out
					.println("Path construction & validation successful!  Certificate is valid!");
			valid = true;

			String p7bfile = this.ee.getSubjectX500Principal().getName() + ".p7b";
			if (debug) {
				System.out.println("Saving validated certificate path to: "
						+ p7bfile);
			}
			fvpath = new FileOutputStream(p7bfile);
			byte[] vpath = cp.getEncoded("PKCS7");
			fvpath.write(vpath);
			fvpath.flush();

		} catch (Throwable e) {
			e.printStackTrace();
		} finally {
			fvpath.close();
		}
		return valid;
	}

}