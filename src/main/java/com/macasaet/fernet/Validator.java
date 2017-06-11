package com.macasaet.fernet;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * This class validates a token according to the Fernet specification. It may be
 * extended to provide domain-specific validation of the decrypted content of
 * the token. If you use a dependency injection / inversion of control
 * framework, it would be appropriate for a subclass to be a singleton which
 * accesses a data store.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public interface Validator<T> {

	default Clock getClock() {
		return Clock.systemUTC();
	}

	default TemporalAmount getTimeToLive() {
		return Duration.ofSeconds(60);
	}

	default TemporalAmount getMaxClockSkew() {
		return Duration.ofSeconds(60);
	}

	default Predicate<T> getObjectValidator() {
		return (T) -> true;
	}

	Function<String, T> getTransformer();

	default T validateAndDecrypt(final Key key, final Token token) throws TokenValidationException {
		final Instant now = Instant.now(getClock());
		final String plainText = token.validateAndDecrypt(key, now.minus(getTimeToLive()), now.plus(getMaxClockSkew()));
		final T object = getTransformer().apply(plainText);
		if (!getObjectValidator().test(object)) {
			throw new TokenValidationException("Invalid token contents.");
		}
		return object;
	}

}