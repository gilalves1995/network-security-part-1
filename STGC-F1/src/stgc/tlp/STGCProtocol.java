package stgc.tlp;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import stgc.exceptions.IntegrityAttackException;
import stgc.utils.Utils;

public class STGCProtocol {
	
	// Attacks 
	private static final String INTEGRITY_ATTACK = "An integrity attack was detected.";
	private static final String REPLAY_ATTACK = "A replay attack was detected.";
	
	
	// Errors 
	private static final String INVALID_KEY_EXCEPTION = "The key is invalid.";
	private static final String SHORT_BUFFER_EXCEPTION = "The buffer is too short.";
	private static final String ILLEGAL_BLOCK_SIZE_EXCEPTION = "Illegal block size.";
	private static final String BAD_PADDING_EXCEPTION = "Bad padding.";
	private static final String WRONG_PASS = "The inserted password is not correct for this group.";
	private static final String INVALID_ALG_PARAM_EXCEPTION = "Invalid parameter was passed.";
		
	// Security constants 
	private static final String DEFAULT_PROVIDER = "BC";
	private static final String SECURITY_CONFIG_FILE = "stgc/ciphersuite.conf";
	private static final String KEYSTORE_FILE = "stgc/keystore.jceks";
	
	
		
	// Protocol STGC constants 
	private static final int VERSION = 1;
	private static final int RELEASE = 1;
	private static final byte SEPARATOR = 0X00;
	public static final byte PAYLOAD_TYPE_M = 0x20;
	public static final byte PAYLOAD_TYPE_S = 0x10;
	public static final int NONCE_SIZE = 4;
	public static final int HEAD_SIZE = 6;
	  
	
	// Protocol needed variables
	private final byte versionRelease;
	private SecureRandom random;
	private NonceStorage storage;
	
	// Security Properties
	private KeyStore keystore; 
	private int ksSize, kmSize, kaSize;
	private String macKmAlg, macKaAlg;
	private Key ks, km, ka;
	private Cipher cipher;
	private Mac mac;
	private String blockMode;
	byte[] defaultCipherIv;
	byte [] defaultMacIv;
	
	public STGCProtocol() {
		
		versionRelease = Byte.parseByte(Integer.toBinaryString(VERSION + 0b10000).substring(1) + 
				Integer.toBinaryString(RELEASE + 0b10000).substring(1), 2);
		
		storage = new NonceStorage();
		random = new SecureRandom();
		
		defaultCipherIv = new byte[] { 
			(byte)0xb0, (byte)0x7b, (byte)0xf5, 
			(byte)0x22, (byte)0xc8, (byte)0xb0,
            (byte)0xd6, (byte)0x08, (byte)0xb8,   
            (byte)0xf5, (byte)0x22, (byte)0xc8, 
            (byte)0xd6, (byte)0x08, (byte)0xb8, 
            (byte)0x7b
         };
		
		defaultMacIv = new byte [] {
			(byte)0xd6, (byte)0x08, (byte)0xb8,   
		    (byte)0xf5, (byte)0x22, (byte)0xc8, 
		    (byte)0xd6, (byte)0x08, (byte)0xb8,
		    (byte)0x22, (byte)0xc8, (byte)0xb0
		};
	}
	
	public Key getSessionKey() {
		return ks;
	}
	
	public Key getMacIntegrityKey() {
		return km;
	}
	
	public Key getMacAtackControlKey() {
		return ka;
	}
	
	// Builds the head of the protocol
	public byte [] buildHead(byte payloadType, short payloadSize) {
		return new byte[] {versionRelease, SEPARATOR, payloadType, SEPARATOR, (byte)((payloadSize >> 8) & 0xff), 
				(byte)(payloadSize & 0xff)};
	}
	
	// Builds the payload of the protocol
	public byte [] buildPayload(byte [] mp)  {
		byte [] ciphertext, payload; 
		try {
			//iv = cipher.getIV();
			initializeEncryption();
			ciphertext = new byte[cipher.getOutputSize(mp.length + mac.getMacLength())];
			int ctLength = cipher.update(mp, 0, mp.length, ciphertext, 0);	
			mac.init(km);
			mac.update(mp);
			ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), ciphertext, ctLength);
			
				
			// After having ciphertext copy it to payload
			payload = new byte[ciphertext.length + mac.getMacLength()];
			System.arraycopy(ciphertext, 0, payload, 0, ctLength);
				
			mac.init(ka);
			mac.update(ciphertext, 0, ciphertext.length);
				
			//After having mactext copy it to payload
			System.arraycopy(mac.doFinal(), 0, payload, ctLength, mac.getMacLength());	
			return payload;
			
		} catch (InvalidKeyException e) {
			System.out.println(INVALID_KEY_EXCEPTION);
			e.printStackTrace();
		} catch (ShortBufferException e) {
			System.out.println(SHORT_BUFFER_EXCEPTION);
		} catch(BadPaddingException e) {
			System.out.println(BAD_PADDING_EXCEPTION);
		} catch(IllegalBlockSizeException e) {
			System.out.println(ILLEGAL_BLOCK_SIZE_EXCEPTION);
		}
		return null;
	}
	
	// Checks message integrity
	public byte [] checkIntegrity(byte [] payload, Key key) throws IntegrityAttackException  {
		byte [] ciphertext, macBytes;
			
		int messageLength = payload.length - mac.getMacLength();
		ciphertext = new byte[messageLength];
		macBytes = new byte[mac.getMacLength()];
		System.arraycopy(payload, 0, ciphertext, 0, messageLength);
		System.arraycopy(payload, messageLength, macBytes, 0, mac.getMacLength());
		
		try {
			mac.init(key);
			mac.update(ciphertext, 0, ciphertext.length);
		
			if(!MessageDigest.isEqual(mac.doFinal(),  macBytes))
				throw new IntegrityAttackException(INTEGRITY_ATTACK);
			return ciphertext;
		} catch (InvalidKeyException e) {
			System.out.println(INVALID_KEY_EXCEPTION);
		}
		return null;
	}
	
	// Decrypt message
	public byte [] decrypt(byte [] ciphertext) {
		try {
			initializeDecryption();
			return cipher.doFinal(ciphertext);
		} catch (InvalidKeyException e) {
			System.out.println(INVALID_KEY_EXCEPTION);
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println(BAD_PADDING_EXCEPTION);
		} catch(IllegalBlockSizeException e) {
			System.out.println(ILLEGAL_BLOCK_SIZE_EXCEPTION);
		} 
		return null;
	}
	
	// Initializes mac
	/*
	private void initializeMac(String keyString) throws InvalidKeyException {
		if(keyString.equals("km")) {
			switch (macKmAlg) {
			case "HMacSHA1": mac.init(km); break;
			case "RC6GMAC": mac.init(new ParametersWithIV(km, defaultMacIv));
			}
		} else if(keyString.equals("ka")) {
			switch(macKaAlg) {
			case "HMacSHA1":
			}
		}
	}
	*/

	// Initializes encryption based on block mode
	private void initializeEncryption() throws InvalidKeyException {
		if(blockMode.equals("CTR") || blockMode.equals("CBC")) {
			try {
				cipher.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(defaultCipherIv));
			} catch (InvalidAlgorithmParameterException e) {
				System.out.println(INVALID_ALG_PARAM_EXCEPTION);
			}
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, ks);
		}
	}
	
	// Initializes decryption based ob block mode
	private void initializeDecryption() throws InvalidKeyException {	
		if(blockMode.equals("CTR") || blockMode.equals("CBC")) {
			try {
				cipher.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(defaultCipherIv));
			} catch (InvalidAlgorithmParameterException e) {
				System.out.println(INVALID_ALG_PARAM_EXCEPTION);
			}
		}
		else {
			cipher.init(Cipher.DECRYPT_MODE, ks);
		}
	}
	
	// Generates a nonce to be used against replay attacks 
	public byte [] generateNonce() {
		byte [] randomBytes = new byte[NONCE_SIZE];
		random.nextBytes(randomBytes);
		return randomBytes;
	}
	
	// Adds a new nonce to the storage
	public void addNonce(int nonce) {
		storage.add(nonce);
	}
	
	// Verifies if the nonce in argument already exists
	public boolean contains(int nonce) {
		return storage.contains(nonce);
	}
	
	// Initializes keystore given the password
	public KeyStore initializeKeystore(String password) {
		try {
			keystore = new KeyStore(KEYSTORE_FILE, password);
			return keystore;
		} catch (Exception e) {
			System.out.println(WRONG_PASS);
		}
		return null;
	}
	
	// Does the security configuration of the protocol based on external info
	public void securityConfig(String multicastGroup) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {	
		String [] properties = Utils.readCiphersuiteFile(SECURITY_CONFIG_FILE, multicastGroup);
		String ciphersuite = properties[0];
		ksSize = Integer.parseInt(properties[1]);
		macKmAlg = properties[2];
		kmSize = Integer.parseInt(properties[3]);
		macKaAlg = properties[4];
		kaSize = Integer.parseInt(properties[5]);
		
		// Store block mode
		blockMode = ciphersuite.split("/")[1];

		cipher = Cipher.getInstance(ciphersuite, DEFAULT_PROVIDER);
		mac = Mac.getInstance(macKmAlg, DEFAULT_PROVIDER);
		
		printConfigurations(properties);
			
		try {
			ks = keystore.getKey("ks");
			km = keystore.getKey("km");
			ka = keystore.getKey("ka");

		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}	
	
	// Prints the security configurations 
	private void printConfigurations(String [] properties) {
		System.out.println("CIPHERSUITE: " + properties[0]);
		System.out.println("SESSION KEY SIZE " + properties[1]);
		System.out.println("MAC KM ALG: " + properties[2]);
		System.out.println("KM SIZE: " + properties[3]);
		System.out.println("MAC KA ALG: " + properties[4]);
		System.out.println("KA SIZE: " + properties[5]);
	}
}
