package com.macasaet.fernet;

/**
 * This exception indicates that a Fernet token could not be created because one or more of the parameters was invalid.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class InvalidTokenException extends IllegalArgumentException {

	private static final long serialVersionUID = 8019898267609912205L;

	public InvalidTokenException(final String s) {
		super(s);
	}

	public InvalidTokenException(final Throwable cause) {
		this(cause.getMessage(), cause);
	}

	public InvalidTokenException(final String message, final Throwable cause) {
		super(message, cause);
	}

}