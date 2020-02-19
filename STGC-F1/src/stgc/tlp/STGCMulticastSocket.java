package stgc.tlp;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.nio.ByteBuffer;

import stgc.exceptions.IntegrityAttackException;

public class STGCMulticastSocket extends MulticastSocket {

	// Socket attributes
	private InetAddress group; 	
	private int port;
	private STGCProtocol stgc;
	
	// change after - needs to be provided to the protocol 
	private String username;
	
	public STGCMulticastSocket(int port, STGCProtocol stgc, String username) throws IOException {
		super(port);
		this.port = port;
		this.stgc = stgc;
		this.username = username;
	}
	
	public void joinGroup(InetAddress multicastAddress) throws IOException {
		group = multicastAddress;
		super.joinGroup(group);
	}
	
	public void send(DatagramPacket packet) throws IOException {
		
		byte [] messageBytes = packet.getData();
		byte [] nonce = stgc.generateNonce();
		byte [] formattedUsername = appendEndOfLine(username);
			
		byte [] mp = new byte [formattedUsername.length + nonce.length + messageBytes.length];
		System.arraycopy(formattedUsername, 0, mp, 0, formattedUsername.length);
		System.arraycopy(nonce, 0, mp, formattedUsername.length, nonce.length);
		System.arraycopy(messageBytes, 0, mp, formattedUsername.length + nonce.length, messageBytes.length);
			
		byte[] head, payload;
		payload = stgc.buildPayload(mp);
		
		short payloadSize = (short)(payload.length);
		head = stgc.buildHead(STGCProtocol.PAYLOAD_TYPE_M, payloadSize);

		byte [] data = new byte[head.length + payload.length];
		System.arraycopy(head, 0, data, 0, head.length);
		System.arraycopy(payload, 0, data, head.length, payload.length);

		//DatagramPacket toSend = new DatagramPacket(data, data.length, group, port);
		DatagramPacket toSend = new DatagramPacket(data, data.length, packet.getAddress(), packet.getPort());
				
		super.send(toSend);
	}
	
	
	public void receive(DatagramPacket packet) throws IOException {
		byte [] ciphertext, plaintext, mpBytes, head, payload;
		
		super.receive(packet);
		
		byte [] data = packet.getData();
		
		head = new byte [STGCProtocol.HEAD_SIZE];
		payload = new byte [packet.getLength() - STGCProtocol.HEAD_SIZE];
		System.arraycopy(data, 0, head, 0, STGCProtocol.HEAD_SIZE);
		System.arraycopy(data, STGCProtocol.HEAD_SIZE, payload, 0, packet.getLength() - STGCProtocol.HEAD_SIZE);
		
		// change to exception release after
		try {
			ciphertext = stgc.checkIntegrity(payload, stgc.getMacAtackControlKey());
			plaintext = stgc.decrypt(ciphertext);
			mpBytes = stgc.checkIntegrity(plaintext, stgc.getMacIntegrityKey()); 
				
			String username =  (new String(mpBytes)) .split("\0")[0];
						
			byte [] nonceBytes = new byte[STGCProtocol.NONCE_SIZE]; 
			System.arraycopy(mpBytes, username.length() + 1, nonceBytes, 0, STGCProtocol.NONCE_SIZE);
			int nonce = ByteBuffer.wrap(nonceBytes).getInt();
						
			int messageLength = mpBytes.length - (username.length() + 1 + STGCProtocol.NONCE_SIZE);
			byte [] messageBytes = new byte[messageLength];
			System.arraycopy(mpBytes, username.length() + STGCProtocol.NONCE_SIZE + 1, messageBytes, 0, messageLength);
						
			//System.out.println("\nUSERNAME: " + username);
			//System.out.println("NONCE: " + nonce);
			//System.out.println("MESSAGE: " + new String (messageBytes));
						
			// Check if the nonce is already stored to avoid message replay attacks
			if(!stgc.contains(nonce)) {
				stgc.addNonce(nonce);

				byte toReceive [] = new byte[packet.getData().length];
				System.arraycopy(messageBytes, 0, toReceive, 0, messageBytes.length);
						
				packet.setData(toReceive, 0, packet.getData().length);	
			}		
		} catch (IntegrityAttackException e) {
			System.out.println(e.getMessage());
		}
	}
	
	
	// Auxiliar methods
	private byte [] appendEndOfLine(String line) {
		StringBuilder b = new StringBuilder();
		b.append(line);
		b.append('\0');
		return b.toString().getBytes();
	}
}