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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;

import java.io.UnsupportedEncodingException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.spec.IvParameterSpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class StringValidatorTest {

    private Clock clock;
    private Key key;
    private StringValidator validator;

    @Before
    public void setUp() throws Exception {
        clock = Clock.fixed(Instant.now(), ZoneId.of("UTC"));
        key = spy(Key.generateKey());
        validator = new StringValidator() {
            public Clock getClock() {
                return clock;
            }
        };
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void verifyPlainTextCleared() throws UnsupportedEncodingException {
        // given
        final String plainText = "plainText";
        final Token token = Token.generate(key, plainText);
        final AtomicReference<byte[]> byteReference = new AtomicReference<byte[]>();
        doAnswer(new Answer<byte[]>() {
            public byte[] answer(final InvocationOnMock invocation) throws Throwable {
                final byte[] retval = (byte[])invocation.callRealMethod();
                byteReference.set(retval);
                return retval;
            }
        }).when(key).decrypt(any(byte[].class), any(IvParameterSpec.class));

        // when
        final String result = validator.validateAndDecrypt(key, token);

        // then
        assertEquals(plainText, result);
        // verify the intermediate representation was cleared
        assertNotEquals(plainText.getBytes("UTF-8"), byteReference.get());
    }

}