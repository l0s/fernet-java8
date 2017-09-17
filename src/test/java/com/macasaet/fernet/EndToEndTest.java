package com.macasaet.fernet;

import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;
import java.util.Random;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * This test eschews the use of mocks to validate the full lifecycle of token creation and validation.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class EndToEndTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private Random random = new SecureRandom();
    private Validator<String> validator = new StringValidator() {
    };

    @Test
    public final void testValidKey() {
        // given
        final Key key = Key.generateKey(random);
        final Token token = Token.generate(random, key, "secret message");

        // when
        final String result = token.validateAndDecrypt(key, validator);

        // then
        assertEquals("secret message", result);
    }

    @Test
    public final void testInvalidKey() {
        // given
        final Token token = Token.generate(random, Key.generateKey(random), "secret message");

        // when
        thrown.expect(TokenValidationException.class);
        token.validateAndDecrypt(Key.generateKey(random), validator);

        // then (nothing)
    }

}