/*
   Copyright 2022 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.TokenValidationException;
import com.macasaet.fernet.Validator;

/**
 * This fuzzer simulates an attacker who does not have access to create a valid token (e.g. no login to the system)
 * attempting to craft a malicious token that does not rely on knowledge of the private signing or encryption keys.
 */
public class TokenDecryptFuzzer {

    /*
     * Run each fuzz input against the same key. Note that in practice, the key is likely rotated on a regular basis.
     */
    final static Key key = new Key("UrNImCIJQuYODgrBU5NgH5rpTc7l52IS5ELuhwF4RHU=");
    final static Validator<byte[]> validator = () -> Function.identity();

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
        final var ivBytes = new byte[16];
        for (int i = ivBytes.length; --i >= 0; ivBytes[i] = data.consumeByte()) ;
        final var initializationVector = new IvParameterSpec(ivBytes);
        final var cipherTextLength = data.consumeInt(1, 4096) * 16;
        final var cipherText = new byte[cipherTextLength];
        for (int i = cipherTextLength; --i >= 0; cipherText[i] = data.consumeByte()) ;
        final var signature = new byte[32];
        for (int i = signature.length; --i >= 0; signature[i] = data.consumeByte()) ;
        final var timestamp = Instant.now().plus(Duration.ofSeconds(data.consumeLong(-60, 60)));
        final var token = new Token((byte) -128, timestamp, initializationVector, cipherText, signature) {
        };
        try {
            token.validateAndDecrypt(key, validator);
            throw new IllegalStateException("Random input passed validation");
        } catch (final TokenValidationException tve) {
            if(tve.getCause() instanceof BadPaddingException) {
                throw new IllegalStateException("Random input forged signature");
            }
        }
    }
}
