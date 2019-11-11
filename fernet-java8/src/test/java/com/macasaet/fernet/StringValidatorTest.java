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
import static org.junit.Assert.assertFalse;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.UnsupportedEncodingException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class StringValidatorTest {

    private Clock clock;
    private Key key;
    private StringValidator validator;

    @Before
    public void setUp() throws Exception {
        clock = Clock.fixed(Instant.now(), ZoneId.of("UTC"));
        key = Key.generateKey();
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
        final byte[] plainBytes = plainText.getBytes("UTF-8");
        final Token token = mock(Token.class);
        given(token.validateAndDecrypt(key, clock.instant().minus(validator.getTimeToLive()),
                clock.instant().plus(validator.getMaxClockSkew()))).willReturn(plainBytes);

        // when
        final String result = validator.validateAndDecrypt(key, token);

        // then
        assertEquals(plainText, result);
        // verify the intermediate representation was cleared
        assertFalse(Arrays.equals(plainBytes, plainText.getBytes("UTF-8")));
    }

}