package stgc.exceptions;

public class IntegrityAttackException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public IntegrityAttackException() {
		super();
	}
	
	public IntegrityAttackException(String message) {
		super(message);
	}
	
	public IntegrityAttackException(String message, Throwable cause) {
		super(message, cause);
	}
	
}
