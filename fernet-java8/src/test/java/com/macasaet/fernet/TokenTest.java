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

import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mutabilitydetector.unittesting.AllowedReason.allowingForSubclassing;
import static org.mutabilitydetector.unittesting.AllowedReason.assumingFields;
import static org.mutabilitydetector.unittesting.AllowedReason.provided;
import static org.mutabilitydetector.unittesting.MutabilityAssert.assertInstancesOf;
import static org.mutabilitydetector.unittesting.MutabilityMatchers.areImmutable;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.IntStream;

import javax.crypto.spec.IvParameterSpec;

import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the {@link Token} class.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class TokenTest {

	private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

	private Validator<String> validator;

    @Before
    public void setUp() {
        validator = new StringValidator() {
        };
    }

    @Test
    public void testFromString() {
        // given
        final String string = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==";

        // when
        final Token result = Token.fromString(string);

        // then
        assertEquals((byte) 0x80, result.getVersion());
        assertEquals(Instant.from(formatter.parse("1985-10-26T01:20:00-07:00")), result.getTimestamp());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                result.getInitializationVector().getIV());
    }

    @Test
    public void testGenerate() {
        // given
        final SecureRandom deterministicRandom = new SecureRandom() {
            private static final long serialVersionUID = 3075400891983079965L;

            public void nextBytes(final byte[] bytes) {
                for (int i = bytes.length; --i >= 0; bytes[i] = 1);
            }
        };
        final Key key = Key.generateKey(deterministicRandom);

        // when
        final Token result = Token.generate(deterministicRandom, key, "Hello, world!");

        // then
        final String plainText = result.validateAndDecrypt(key, validator);
        assertEquals("Hello, world!", plainText);
    }

    @Test
    public void testGenerateEmptyToken() {
        // given
        final SecureRandom deterministicRandom = new SecureRandom() {
            private static final long serialVersionUID = 3075400891983079965L;

            public void nextBytes(final byte[] bytes) {
                for (int i = bytes.length; --i >= 0; bytes[i] = 1);
            }
        };
        final Key key = Key.generateKey(deterministicRandom);

        // when
        final Token result = Token.generate(deterministicRandom, key, "");

        // then
        final String plainText = result.validateAndDecrypt(key, validator);
        assertEquals("", plainText);
    }

    @Test
    public void testDecryptKey() {
        // given
        final SecureRandom deterministicRandom = new SecureRandom() {
            private static final long serialVersionUID = 3075400891983079965L;

            public void nextBytes(final byte[] bytes) {
                for (int i = initializationVectorBytes; --i >= 0; bytes[i] = 1);
            }
        };
        final Key key = new Key(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
                new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
        final Token token = Token.generate(deterministicRandom, key, "Hello, world!");

        // when
        final String result = token.validateAndDecrypt(key, validator);

        // then
        assertEquals("Hello, world!", result);
    }

    @Test
    public void testSerialise() {
        // given
        final IvParameterSpec initializationVector = new IvParameterSpec(
                new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
        final Token invalidToken = new Token((byte) 0x80, Instant.ofEpochSecond(0), initializationVector,
                new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, new byte[] {1, 2, 3, 4, 5, 6, 7, 8,
                    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});

        // when
        final String result = invalidToken.serialise();

        // then
        assertEquals(
                "gAAAAAAAAAAAAQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODxABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA==",
                result);
    }

    @Test
    public final void verifyExceptionThrownWhenKeyNoLongerInRotation() {
        // given
        final SecureRandom random = new SecureRandom();
        final Token token = Token.generate(random, Key.generateKey(random), "Don't wait too long to decrypt this!");

        final List<? extends Key> decryptionKeys =
                IntStream.range(0, 16).mapToObj(i -> Key.generateKey(random)).collect(toList());

        // when / then
        assertThrows(TokenValidationException.class, () -> token.validateAndDecrypt(decryptionKeys, validator));
    }

    @Test
    public final void verifyKeyInRotationCanDecryptToken() {
        // given
        final SecureRandom random = new SecureRandom();
        final List<? extends Key> decryptionKeys =
                IntStream.range(0, 16).mapToObj(i -> Key.generateKey(random)).collect(toList());
        final Token token = Token.generate(random, decryptionKeys.get(8), "Don't wait too long to decrypt this!");

        // when
        final String result = token.validateAndDecrypt(decryptionKeys, validator);

        // then
        assertEquals("Don't wait too long to decrypt this!", result);
    }

    @Test
    public final void verifyTextTokenGenerationWithDefaultEntropySource() {
        // given
        final Key key = Key.generateKey();

        // when
        final Token result = Token.generate(key, "message");

        // then
        final String message = result.validateAndDecrypt(key, new StringValidator() {
        });
        assertEquals("message", message);
    }

    @Test
    public final void verifyTokenGenerationWithDefaultEntropySource() {
        // given
        final Key key = Key.generateKey();

        // when
        final Token result = Token.generate(key, new byte[] {1, 1, 2, 3, 5, 8, 13, 21});

        // then
        assertTrue(result.isValidSignature(key));
    }

    @Test
    public final void verifyImmutable() {
        assertInstancesOf(Token.class, areImmutable(),
                allowingForSubclassing(),
                provided(IvParameterSpec.class).isAlsoImmutable(),
                assumingFields("cipherText", "hmac").areNotModifiedAndDoNotEscape());
    }

}