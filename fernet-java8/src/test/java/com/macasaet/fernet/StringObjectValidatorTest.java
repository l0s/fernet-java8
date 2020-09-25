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

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;

public class StringObjectValidatorTest {

    protected static class Pojo {
        UUID id;
        String username;
        URL avatar;
    }

    protected Pojo deserialise(final String line) {
        final String[] components = line.split(",");
        final Pojo retval = new Pojo();
        retval.id = UUID.fromString(components[0]);
        retval.username = components[1];
        try {
            retval.avatar = new URL(components[2]);
        } catch (final MalformedURLException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return retval;
    }

    private final StringObjectValidator<Pojo> validator = new StringObjectValidator<StringObjectValidatorTest.Pojo>() {
        public Function<String, Pojo> getStringTransformer() {
            return StringObjectValidatorTest.this::deserialise;
        }
    };

    private Key key;

    @Before
    public void setUp() {
        key = Key.generateKey();
    }

    @Test
    public void testValidateAndDecryptKeyToken() throws MalformedURLException {
        // given
        final Token token = Token.generate(key,
                "924dbb99-f3c8-4c64-ab01-265bc30b603c,methoataske,https://static.example.com/images/fa0ce2c1-0789-4ea3-9629-00e6867cb0d5.png");

        // when
        final Pojo result = validator.validateAndDecrypt(key, token);

        // then
        assertEquals(UUID.fromString("924dbb99-f3c8-4c64-ab01-265bc30b603c"), result.id);
        assertEquals("methoataske", result.username);
        assertEquals(new URL("https", "static.example.com", "/images/fa0ce2c1-0789-4ea3-9629-00e6867cb0d5.png"),
                result.avatar);
    }

    @Test
    public void testValidateAndDecryptCollectionOfQextendsKeyToken() throws MalformedURLException {
        // given
        final Token token = Token.generate(key,
                "bea985b3-3ae8-4a4a-bbd1-c62e607f1319,bevan,https://static.example.com/images/e00ec8e3-581a-4e08-95c5-493f02466376.png");

        // when
        final Pojo result = validator.validateAndDecrypt(asList(Key.generateKey(), key, Key.generateKey()), token);

        // then
        assertEquals(UUID.fromString("bea985b3-3ae8-4a4a-bbd1-c62e607f1319"), result.id);
        assertEquals("bevan", result.username);
        assertEquals(new URL("https", "static.example.com", "/images/e00ec8e3-581a-4e08-95c5-493f02466376.png"),
                result.avatar);
    }

}
