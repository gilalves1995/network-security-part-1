package stgc.utils;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;


public class Utils {
	
	private static String digits = "0123456789abcdef";
	
	// Reads ciphersuite configuration file 
	public static String [] readCiphersuiteFile(String filename, String multicastGroup) {
		String [] properties = new String[6];
		
		String line;
		try {
			FileReader reader = new FileReader(filename);
			BufferedReader buffer = new BufferedReader(reader);
			while((line = buffer.readLine()) != null) {
    			if(line.charAt(0) == '<' && line.charAt(1) != '/') {
    				String group = line.substring(1, line.length()-1);
    				if(("/" + group).equals(multicastGroup)) {
    					int i = 0;
    					while(i < 6) {
        					String [] props = buffer.readLine().split(":");
        					properties[i] = props[1].trim();
    						i++;
        				}
    					break;
    				}	
    			}
    			
            }
			buffer.close();
		} catch(FileNotFoundException e) {
			System.out.println("File was not found.");
		} catch(IOException e) {
    		System.out.println("Error reading file.");
    	}
		
		return properties;
	}
	
	// Returns a string in hex 
	public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();
        
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;
            
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
  
	// Returns a string in hex
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }
  
}
