package com.macasaet.fernet;

/**
 * This exception indicates that a Fernet token could not be created because one or more of the parameters was invalid.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class IllegalTokenException extends IllegalArgumentException {

    private static final long serialVersionUID = 8019898267609912205L;

    public IllegalTokenException(final String message) {
        super(message);
    }

    public IllegalTokenException(final String message, final Throwable cause) {
        super(message, cause);
    }

}