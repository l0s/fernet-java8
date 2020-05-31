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

import static com.macasaet.fernet.Constants.encoder;
import static com.macasaet.fernet.Constants.encryptionKeyBytes;
import static com.macasaet.fernet.Constants.signingKeyBytes;
import static nl.jqno.equalsverifier.Warning.ALL_FIELDS_SHOULD_BE_USED;
import static nl.jqno.equalsverifier.Warning.STRICT_INHERITANCE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mutabilitydetector.unittesting.AllowedReason.allowingForSubclassing;
import static org.mutabilitydetector.unittesting.AllowedReason.assumingFields;
import static org.mutabilitydetector.unittesting.MutabilityAssert.assertInstancesOf;
import static org.mutabilitydetector.unittesting.MutabilityMatchers.areImmutable;

import java.security.SecureRandom;
import java.time.Instant;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.api.SingleTypeEqualsVerifierApi;

/**
 * Unit tests for the {@link Key} class.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class KeyTest {

    @Test
    public final void testConstructorValidatesSigningKey() {
        // given
        final byte[] invalidSigningKey = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        final byte[] validEncryptionKey = new byte[] {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        try {
            // when
            new Key(invalidSigningKey, validEncryptionKey);
            fail("Expected validation exception");
            // then
        } catch (final IllegalArgumentException iae) {
        }
    }

    @Test
    public final void testConstructorValidatesEncryptionKey() {
        // given
        final byte[] validSigningKey = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        final byte[] invalidEncryptionKey = new byte[] {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        try {
            // when
            new Key(validSigningKey, invalidEncryptionKey);
            fail("Expected validation exception");
            // then
        } catch (final IllegalArgumentException iae) {
        }
    }

    @Test
    public final void testConstructorMakesSafeCopies() {
        // given
        final byte[] signingKey = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        final byte[] encryptionKey = new byte[] {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

        // when
        final Key key = new Key(signingKey, encryptionKey);
        signingKey[0] = 0;
        encryptionKey[0] = 0;

        // then
        assertEquals(1, key.getSigningKeySpec().getEncoded()[0]);
        assertEquals(17, key.getEncryptionKeySpec().getEncoded()[0]);
    }

    @Test
    public final void testFromString() {
        // given
        final String string = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

        // when
        final Key key = new Key(string);

        // then
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
                key.getSigningKeySpec().getEncoded());
        assertArrayEquals(new byte[] {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
                key.getEncryptionKeySpec().getEncoded());
    }

    @Test
    public void testGenerateKey() {
        // given
        final SecureRandom deterministicRandom = new SecureRandom() {

            private static final long serialVersionUID = 6548702184401342900L;

            public void nextBytes(final byte[] bytes) {
                for (int i = signingKeyBytes; --i >= 0; bytes[i] = 1);
            }
        };

        // when
        final Key result = Key.generateKey(deterministicRandom);

        // then
        final byte[] signingKey = result.getSigningKeySpec().getEncoded();
        for (int i = signingKeyBytes; --i >= 0;) {
            assertEquals(1, signingKey[i]);
        }
        final byte[] encryptionKey = result.getEncryptionKeySpec().getEncoded();
        for (int i = encryptionKeyBytes; --i >= 0;) {
            assertEquals(1, encryptionKey[i]);
        }
    }

    @Test
    public void testGetHmac() {
        // given
        final Key key = new Key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");

        // when
        final byte[] result = key.sign((byte) 0x80, Instant.ofEpochSecond(1), new IvParameterSpec(new byte[] {2}),
                new byte[] {3});

        // then
        assertEquals("WvLIvt4MSCQKgeLyvltUqN8O7mvcozhsEAgIiytxypw=", encoder.encodeToString(result));
    }

    @Test
    public void testGetSigningKeySpec() {
        // given
        final Key key = new Key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");

        // when
        final java.security.Key result = key.getSigningKeySpec();

        // then
        assertEquals("HmacSHA256", result.getAlgorithm());
    }

    @Test
    public void testGetEncryptionKeySpec() {
        // given
        final Key key = new Key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");

        // when
        final SecretKeySpec result = key.getEncryptionKeySpec();

        // then
        assertEquals("AES", result.getAlgorithm());
    }

    @Test
    public void testSerialise() {
        // given
        final Key key = new Key(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
                new byte[] {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});

        // when
        final String result = key.serialise();

        // then
        assertEquals("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", result);
    }

    @Test
    public final void verifyEqualityContract() {
        // given
        final SingleTypeEqualsVerifierApi<Key> verifier =
                EqualsVerifier.forClass(Key.class).suppress(STRICT_INHERITANCE).suppress(ALL_FIELDS_SHOULD_BE_USED);

        // when / then
        verifier.verify();
    }

    @Test
    public final void verifyImmutable() {
        assertInstancesOf(Key.class, areImmutable(),
                allowingForSubclassing(),
                assumingFields("signingKey", "encryptionKey").areNotModifiedAndDoNotEscape());
    }

}