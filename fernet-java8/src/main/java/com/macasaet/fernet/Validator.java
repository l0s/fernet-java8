/**
   Copyright 2017 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package com.macasaet.fernet;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAmount;
import java.util.Collection;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * This class validates a token according to the Fernet specification. It may be extended to provide domain-specific
 * validation of the decrypted content of the token. If you use a dependency injection / inversion of control framework,
 * it would be appropriate for a subclass to be a singleton which accesses a data store.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @param <T>
 *            The type of the payload. The Fernet token encodes the payload in binary. The type T should be a domain
 *            object or data transfer object representation of that data.
 * @see StringObjectValidator
 * @see StringValidator
 * @author Carlos Macasaet
 */
public interface Validator<T> {

    /**
     * Override this method if your application uses a custom clock. The default implementation returns a clock in the
     * UTC time zone with second granularity.
     *
     * @return The Clock used for all validation operations.
     */
    default Clock getClock() {
        return Clock.tickSeconds(ZoneOffset.UTC);
    }

    /**
     * Override this method to define the maximum allowable age of a token. Note that the time-to-live (TTL) check is
     * done before applying business rules. So if the {@link Predicate} defined by {@link #getObjectValidator()} applies
     * varying TTL checks depending on the payload (e.g. progressively shorter TTLs), then the TTL specified here must
     * be at least as long as any defined in the Predicate.
     *
     * @return the maximum allowable age of a token
     */
    default TemporalAmount getTimeToLive() {
        return Duration.ofSeconds(60);
    }

    /**
     * Override this method to define a custom acceptable clock skew. Fernet tokens with a timestamp that is too far in
     * the future will be considered invalid. This essentially defines how much tolerance your application has for clock
     * skew between VMs in the system. The default value is 60 seconds.
     *
     * @return the tolerance for clock skew between VMs.
     */
    default TemporalAmount getMaxClockSkew() {
        return Duration.ofSeconds(60);
    }

    /**
     * Implement this to define application-specific security rules. By default, no additional validation is performed.
     *
     * @return a method that implements custom validation logic on the deserialised payload
     */
    default Predicate<T> getObjectValidator() {
        return payload -> true;
    }

    /**
     * Implement this to define how decrypted content is deserialised into domain objects.
     *
     * @return a method for converting the decrypted payload into a domain object
     */
    Function<byte[], T> getTransformer();

    /**
     * Check the validity of the token then decrypt and deserialise the payload.
     *
     * @param key the stored shared secret key
     * @param token the client-provided token of unknown validity 
     * @return the deserialised contents of the token
     * @throws TokenValidationException if the token is invalid.
     */
    @SuppressWarnings({"PMD.LawOfDemeter", "PMD.DataflowAnomalyAnalysis"})
    default T validateAndDecrypt(final Key key, final Token token) {
        final Instant now = Instant.now(getClock());
        final byte[] plainText = token.validateAndDecrypt(key, now.minus(getTimeToLive()), now.plus(getMaxClockSkew()));
        final T object = getTransformer().apply(plainText);
        if (!getObjectValidator().test(object)) {
            for (int i = plainText.length; --i >= 0; plainText[i] = 0);
            throw new PayloadValidationException("Invalid Fernet token payload.");
        }
        return object;
    }

    /**
     * Check the validity of a token against a pool of keys. This is useful if your application uses key rotation. Since
     * token-verification is entirely CPU-bound, an attempt is made to evaluate the keys in parallel based on the
     * available number of processors. If you wish to control the number of parallel threads used, invoke this inside a
     * custom {@link ForkJoinPool}.
     *
     * @param keys
     *            all the non-expired keys that could have been used to generate a token
     * @param token
     *            the client-provided token of unknown validity
     * @return the deserialised contents of the token
     * @throws TokenValidationException
     *             if the token was not generated using any of the supplied keys.
     */
    @SuppressWarnings("PMD.LawOfDemeter")
    default T validateAndDecrypt(final Collection<? extends Key> keys, final Token token) {
        final Key key =
                keys.parallelStream()
                .filter(token::isValidSignature)
                .findFirst()
                .orElseThrow(() -> new TokenValidationException("Encryption key not found."));
        return validateAndDecrypt(key, token);
    }

}