package com.macasaet.fernet;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;

/**
 * This class validates a token according to the Fernet specification. It may be
 * extended to provide domain-specific validation of the decrypted content of
 * the token. If you use a dependency injection / inversion of control
 * framework, it would be appropriate for a subclass to be a singleton which
 * accesses a data store.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @see #validate(String)
 * @author Carlos Macasaet
 */
@Deprecated
public class TokenValidator {

	private final TemporalAmount tokenTimeToLive;
	private final TemporalAmount maxClockSkew;

	/**
	 * Create a new validator with a custom TTL and clock skew
	 * @param tokenTimeToLive how long a token may be used before it is no longer valid
	 * @param maxClockSkew the maximum time in the future a token may without being considered invalid
	 */
	public TokenValidator(final TemporalAmount tokenTimeToLive, final TemporalAmount maxClockSkew) {
		if (tokenTimeToLive == null) {
			throw new IllegalArgumentException("tokenTimeToLive cannot be null");
		}
		if (maxClockSkew == null) {
			throw new IllegalArgumentException("maxClockSkew cannot be null");
		}
		this.tokenTimeToLive = tokenTimeToLive;
		this.maxClockSkew = maxClockSkew;
	}

	/**
	 * Create a new validator with a TTL and max clock skew of 60 seconds.
	 */
	public TokenValidator() {
		this(Duration.ofMinutes(1), Duration.ofMinutes(1));
	}

	/**
	 * Validate the token and return the decrypted contents. Subclasses may
	 * change the behaviour to return a transformation of the contents.
	 *
	 * @param key
	 *            the shared secret key
	 * @param token
	 *            the token provided by the client
	 * @return the decrypted contents
	 * @throws TokenValidationException
	 *             if the token is invalid according to the Fernet specification
	 *             or if it is invalid according to the business rules
	 */
	public String validateAndDecrypt(final Key key, final Token token) throws TokenValidationException {
		final Instant now = Instant.now();
		final String plainText = token.validateAndDecrypt(key, now.minus(getTokenTimeToLive()).getEpochSecond(),
				now.plus(getMaxClockSkew()).getEpochSecond());
		return validate(plainText);
	}

	/**
	 * Override this method to perform domain-specific validation of the decrypted contents of a token.
	 *
	 * @param plainText the decrypted content of a token
	 * @return either the original plain text or a transformation of it according to domain-rules
	 * @throws TokenValidationException if the plain text is not valid
	 */
	protected String validate(final String plainText) throws TokenValidationException {
		return plainText;
	}

	protected TemporalAmount getTokenTimeToLive() {
		return tokenTimeToLive;
	}

	protected TemporalAmount getMaxClockSkew() {
		return maxClockSkew;
	}

}