/**
   Copyright 2019 Carlos Macasaet

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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.openMocks;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.Predicate;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

public class ValidatorTest {

    private AutoCloseable mockContext;
    private Clock clock;
    private Key key;
    @Mock
    private Predicate<byte[]> objectValidator;
    private Validator<byte[]> validator;

    @Before
    public void setUp() throws Exception {
        mockContext = openMocks(this); // there seems to be a bug with @RunWith(MockitoJUnitRunner.class)
        clock = Clock.fixed(Instant.now(), ZoneId.of("UTC"));
        key = Key.generateKey();
        validator = new Validator<byte[]>() {
            public Function<byte[], byte[]> getTransformer() {
                return Function.identity();
            }

            public Clock getClock() {
                return clock;
            }

            public Predicate<byte[]> getObjectValidator() {
                return objectValidator;
            }
        };
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public void verifyPlainTextRetained() {
        // given
        final byte[] plainBytes = new byte[] { 1, 1, 2, 3, 5, 8 };
        final Token token = mock(Token.class);
        given(token.validateAndDecrypt(key, clock.instant().minus(validator.getTimeToLive()),
                clock.instant().plus(validator.getMaxClockSkew()))).willReturn(plainBytes);
        given(objectValidator.test(eq(plainBytes))).willReturn(true);

        // when
        final byte[] result = validator.validateAndDecrypt(key, token);

        // then
        assertTrue(Arrays.equals(result, new byte[] { 1, 1, 2, 3, 5, 8 })); // output the correct plain text
    }

    @Test
    public void verifyPlainTextClearedOnValidationFailure() {
        // given
        final byte[] plainBytes = new byte[] { 1, 1, 2, 3, 5, 8 };
        final Token token = mock(Token.class);
        given(token.validateAndDecrypt(key, clock.instant().minus(validator.getTimeToLive()),
                clock.instant().plus(validator.getMaxClockSkew()))).willReturn(plainBytes);
        given(objectValidator.test(eq(plainBytes))).willReturn(false);

        // when
        assertThrows(PayloadValidationException.class, () -> validator.validateAndDecrypt(key, token));

        // then
        assertFalse(Arrays.equals(plainBytes, new byte[] { 1, 1, 2, 3, 5, 8 })); // verify the intermediate
                                                                                 // representation was cleared
    }
}