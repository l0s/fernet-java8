package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Random;

/**
 * This class creates new Fernet tokens.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Generator {

    private static final Clock clock = Clock.tickSeconds(ZoneOffset.UTC);
    private static final Random entropySource = new SecureRandom();

    /**
     * Override this method if your application uses a custom clock. The default implementation returns a clock in the
     * UTC time zone with second granularity.
     *
     * @return The Clock used for generating all tokens
     */
    protected Clock getClock() {
        return clock;
    }

    /**
     * Override this method if your application uses a custom entropy source.
     *
     * @return an entropy source for generating Fernet token initialisation vectors (IVs)
     */
    protected Random getEntropySource() {
        return entropySource;
    }

    /**
     * Generate a new Fernet token.
     *
     * @param key the secret key for encrypting <em>payload</em> and signing the token
     * @param payload the unencrypted data to embed in the token
     * @return a unique Fernet token
     */
    public Token generate(final Key key, final byte[] payload) {
        return Token.generate(getClock(), getEntropySource(), key, payload);
    }

    /**
     * Generate a new Fernet token.
     *
     * @param key the secret key for encrypting <em>payload</em> and signing the token
     * @param plainText unencrypted text to embedn in the token
     * @return a unique Fernet token
     */
    public Token generate(final Key key, final String plainText) {
        return generate(key, plainText.getBytes(charset));
    }

}