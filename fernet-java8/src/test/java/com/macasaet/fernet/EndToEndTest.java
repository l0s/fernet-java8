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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.security.SecureRandom;

import org.junit.Test;

/**
 * This test eschews the use of mocks to validate the full lifecycle of token creation and validation.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class EndToEndTest {

    private SecureRandom random = new SecureRandom();
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

        // when / then
        assertThrows(TokenValidationException.class, () -> token.validateAndDecrypt(Key.generateKey(random), validator));
    }

}