/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: KeyStoreManager.java 31 2014-07-08 17:06:14Z grandamp@gmail.com $
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
 * @version $Revision: 31 $
 * Last changed: $LastChangedDate: 2014-07-08 11:06:14 -0600 (Tue, 08 Jul 2014) $
 *****************************************************************************/

package org.keysupport.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

/**
 */
public class KeyStoreManager {

	/*
	 * Over time this class will act as a way to access KeyStore(s)/keys 
	 * from software or hardware.
	 */

	private KeyStore keyStore;
		
	public KeyStoreManager() {
		
	}
	
	/**
	 * Method getCertificate.
	 * @param keyStore KeyStore
	 * @param keyAlias String
	 * @return X509Certificate
	 * @throws KeyStoreException
	 */
	public X509Certificate getCertificate(KeyStore keyStore,
			String keyAlias) throws KeyStoreException {

		return (X509Certificate) keyStore.getCertificate(keyAlias);

	}

	/******************************************************************************
	 * 
	 * To change the defalt keystore location, change the following variable in
	 * the file [JAVA_HOME]/lib/java.security:
	 * 
	 * keystore.user=${user.home}${/}.keystore
	 * 
	 * @param password char[]
	 * @param file File
	 * @return KeyStore
	 * @throws KeyStoreException
	 *****************************************************************************/
	public KeyStore getKeyStore(char[] password, File file)
			throws KeyStoreException {

		this.keyStore = KeyStore.getInstance("JCEKS");
		try {
			this.keyStore.load(new FileInputStream(file), password);
		} catch (java.io.FileNotFoundException fnf) {
	        KeyStore keyStore;
			try {
				keyStore = KeyStore.getInstance("JKS");
				keyStore.load(null, null);
				keyStore.store(new FileOutputStream(file), password);
				this.keyStore = keyStore;
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return this.keyStore;

	}

	/*
	 * public static PrivateKey getPrivateKey(KeyStore keyStore, String
	 * keyAlias) throws KeyStoreException, NoSuchAlgorithmException,
	 * UnrecoverableKeyException {
	 * 
	 * return (PrivateKey) keyStore.getKey(keyAlias,
	 * DataUtil.getPIN("Enter Key Password"));
	 * 
	 * }
	 */
	/**
	 * Method getPrivateKey.
	 * @param keyStore KeyStore
	 * @param keyAlias String
	 * @param password char[]
	 * @return PrivateKey
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableKeyException
	 */
	public PrivateKey getPrivateKey(KeyStore keyStore, String keyAlias,
			char[] password) throws KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException {

		return (PrivateKey) keyStore.getKey(keyAlias, password);

	}

	public void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
		this.keyStore.setKeyEntry(alias, key, password, chain);
	}
	
    public void setEntry(String alias, KeyStore.SecretKeyEntry skEntry, char[] password) throws KeyStoreException {
    	 this.keyStore.setEntry(alias, skEntry, new KeyStore.PasswordProtection(password));
    }

	
	public void store(File file, char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		this.keyStore.store(new FileOutputStream(file), password);
	}

	
	/**
	 * Method getSecretKey.
	 * @param keyStore KeyStore
	 * @param keyAlias String
	 * @param password char[]
	 * @return SecretKey
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableKeyException
	 */
	public static SecretKey getSecretKey(KeyStore keyStore, String keyAlias,
			char[] password) throws KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException {

		return (SecretKey) keyStore.getKey(keyAlias, password);

	}

}
