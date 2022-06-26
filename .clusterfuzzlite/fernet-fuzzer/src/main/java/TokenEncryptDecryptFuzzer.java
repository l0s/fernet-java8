import java.util.Arrays;
import java.util.function.Function;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

public class TokenEncryptDecryptFuzzer {

    final static Validator<byte[]> validator = () -> Function.identity();

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
        final var key = Key.generateKey();
        final var payload = data.consumeBytes(4096);
        final var token = Token.generate(key, payload);
        final var serialised = token.serialise();
        final var deserialised = Token.fromString(serialised);
        final var decrypted = deserialised.validateAndDecrypt(key, validator);
        if (!Arrays.equals(payload, decrypted)) {
            throw new IllegalStateException("Encryption/decryption fault");
        }
    }
}
