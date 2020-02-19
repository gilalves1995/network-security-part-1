package stgc.tlp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyStore {
	
	private static final String KEYSTORE_TYPE = "JCEKS";
	
	private java.security.KeyStore keystore;
	private String keystorePassword;
	
	public KeyStore(String keystoreFile, String keystorePassword) throws Exception {
		this.keystorePassword = keystorePassword;
		initialize(keystoreFile, keystorePassword);
	}
		
	// Initializes keystore 
	private void initialize(String keystoreFile, String mainPassword) throws Exception {
		File file = new File(keystoreFile);
		keystore = java.security.KeyStore.getInstance(KEYSTORE_TYPE);
			
		if(file.exists())
			keystore.load(new FileInputStream(file), mainPassword.toCharArray());
		else {
			keystore.load(null, null);
			keystore.store(new FileOutputStream(file), mainPassword.toCharArray());
		}	
	}
	

	// Returns a key based on its signature
	public Key getKey(String entryKey) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		PasswordProtection keyPassword = new PasswordProtection(keystorePassword.toCharArray());
		java.security.KeyStore.Entry entry = keystore.getEntry(entryKey, keyPassword);
		SecretKey keyFound = ((java.security.KeyStore.SecretKeyEntry) entry).getSecretKey();
		return keyFound;
	}
}
