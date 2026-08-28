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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HashMap;
import java.util.UUID;
import java.util.function.Predicate;
import javax.crypto.spec.IvParameterSpec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.macasaet.fernet.*;

/**
 * This fuzzer simulates an attacker padding the content of a token
 */
public class PayloadPaddingFuzzer {

    /**
     * Freeze time for the fuzzer. In practice, the clock will return a different instant every second.
     */
    final static Clock clock = Clock.fixed(Instant.ofEpochSecond(581182474), ZoneId.of("UTC"));
    /**
     * Run each fuzz input against the same key. Note that in practice, the key is likely rotated on a regular basis.
     */
    final static Key key = new Key("UrNImCIJQuYODgrBU5NgH5rpTc7l52IS5ELuhwF4RHU=");
    final static Validator<String> validator = new StringValidator() {
        public Charset getCharset() {
            return StandardCharsets.UTF_8;
        }

        public Clock getClock() {
            return clock;
        }

        public Predicate<String> getObjectValidator() {
            return candidate -> {
                final var components = candidate.split("&");
                final var map = new HashMap<String, String>(components.length);
                for (final var component : components) {
                    final var pair = component.split("=");
                    map.put(pair[0], pair[1]);
                }
                return map.containsKey("id") && map.containsKey("username");
            };
        }
    };
    final static Utility utility = new Utility();

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
        // retrieve a valid token from the server
        final var version = (byte) 0x80;
        final var timestamp = clock.instant();
        final var initializationVector = new IvParameterSpec(Base64.getUrlDecoder().decode("7x-FMghmHjn-6lVUKCsN-A=="));
        final var id = UUID.fromString("5c8293ac-6c70-4be0-823b-6ec391fc164b");
        final var username = "alice";
        final var plain = "id=" + id + "&username=" + username;
        final var cipherText = key.encrypt(plain.getBytes(StandardCharsets.UTF_8), initializationVector);
        final var signature = key.sign(version, timestamp, initializationVector, cipherText);
        final var validToken = new Token(version, timestamp, initializationVector, cipherText, signature) {
        };
        validator.validateAndDecrypt(key, validToken);

        // tamper with the token
        final var forgedTimestamp = timestamp.plusSeconds(data.consumeLong(0, 60));
        final var forgedInitializationVector = new IvParameterSpec(utility.consumeBytes(data, 16));
        final var forgedCipherText = data.consumeBytes(cipherText.length * 2);
        final var forgedSignature = utility.consumeBytes(data, signature.length);
        final var forgedToken = new Token(version, forgedTimestamp, forgedInitializationVector, forgedCipherText, forgedSignature) {
        };
        try {
            final var result = validator.validateAndDecrypt(key, forgedToken);
            if (result.length() > plain.length() && result.startsWith(plain)) {
                throw new FuzzerSecurityIssueHigh("Able to pad a token with a malicious payload");
            }
            throw new FuzzerSecurityIssueHigh("Able to forge a token");
        } catch (final TokenValidationException ignored) {
        }
    }

}
