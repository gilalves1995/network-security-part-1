package stgc.tlp;

import java.util.Hashtable;
import java.util.Map;

public class NonceStorage {
	
	private Map<Long, Integer> storage;
	
	public NonceStorage() {
		storage = new Hashtable<Long, Integer>();
	}
	
	public void add(int nonce) {
		storage.put(System.currentTimeMillis(), nonce);
	}
	
	public boolean contains(int nonce) {
		return storage.containsValue(nonce);
		
	}
}
