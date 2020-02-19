package stgc.exceptions;

public class ReplayAttackException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public ReplayAttackException() {
		super();
	}
	
	public ReplayAttackException(String message) {
		super(message);
	}
	
	public ReplayAttackException(String message, Throwable cause) {
		super(message, cause);
	}
	
}
