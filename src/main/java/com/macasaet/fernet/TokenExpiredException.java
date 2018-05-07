package com.macasaet.fernet;

/**
 * This is a special case of the {@link TokenValidationException} that indicates that the Fernet token is invalid
 * because the application-defined time-to-live has elapsed. Applications can use this to communicate to the client that
 * a new Fernet must be generated, possibly by re-authenticating.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class TokenExpiredException extends TokenValidationException {

    private static final long serialVersionUID = -8250681539503776783L;

    public TokenExpiredException(final String message) {
        super(message);
    }

    public TokenExpiredException(final Throwable cause) {
        this(cause.getMessage(), cause);
    }

    public TokenExpiredException(final String message, final Throwable cause) {
        super(message, cause);
    }

}