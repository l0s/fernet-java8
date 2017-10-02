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
public abstract class Generator {

    private static final Random entropySource = new SecureRandom();

    /**
     * Override this method if your application uses a custom clock. The default implementation returns a clock in the
     * UTC time zone with second granularity.
     *
     * @return The Clock used for generating all tokens
     */
    protected Clock getClock() {
        return Clock.tickSeconds(ZoneOffset.UTC);
    }

    /**
     * Override this method if your application uses a custom entropy source.
     *
     * @return an entropy source for generating Fernet token initialisation vectors (IVs)
     */
    protected Random getEntropySource() {
        return entropySource;
    }

    public Token generate(final Key key, final byte[] payload) {
        return Token.generate(getClock(), getEntropySource(), key, payload);
    }

    public Token generate(final Key key, final String plainText) {
        return generate(key, plainText.getBytes(charset));
    }

}