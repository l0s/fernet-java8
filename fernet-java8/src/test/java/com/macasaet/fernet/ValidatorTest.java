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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;
import static org.mockito.MockitoAnnotations.initMocks;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Predicate;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class ValidatorTest {

    private Clock clock;
    private Key key;
    @Mock
    private Predicate<byte[]> objectValidator;
    private Validator<byte[]> validator;

    @Before
    public void setUp() throws Exception {
        initMocks(this);
        clock = Clock.fixed(Instant.now(), ZoneId.of("UTC"));
        key = spy(Key.generateKey());
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
    }

    @Test
    public void verifyPlainTextRetained() {
        // given
        final byte[] plainBytes = new byte[] { 1, 1, 2, 3, 5, 8 };
        final Token token = Token.generate(key, plainBytes);
        given(objectValidator.test(eq(plainBytes))).willReturn(true);

        // when
        final byte[] result = validator.validateAndDecrypt(key, token);

        // then
        assertArrayEquals(new byte[] { 1, 1, 2, 3, 5, 8 }, result); // output the correct plain text
    }

    @Test
    public void verifyPlainTextClearedOnValidationFailure() {
        // given
        final byte[] plainBytes = new byte[] { 1, 1, 2, 3, 5, 8 };
        final Token token = Token.generate(key, plainBytes);
        final AtomicReference<byte[]> bytesReference = new AtomicReference<>();
        doAnswer(new Answer<byte[]>() {
            public byte[] answer(final InvocationOnMock invocation) throws Throwable {
                final byte[] retval = (byte[]) invocation.callRealMethod();
                bytesReference.set(retval);
                return retval;
            }
        }).when(key).decrypt(token.getCipherText(), token.getInitializationVector());
        given(objectValidator.test(eq(plainBytes))).willReturn(false);

        // when
        assertThrows(PayloadValidationException.class, () -> validator.validateAndDecrypt(key, token));

        // then
        assertFalse(Arrays.equals(bytesReference.get(), new byte[] { 1, 1, 2, 3, 5, 8 })); // verify the intermediate
                                                                                           // representation was cleared
    }
}
