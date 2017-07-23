package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;

import java.nio.charset.Charset;
import java.util.function.Function;

/**
 * A {@link Validator} for String payloads. This is useful if your payload contains unique identifiers like user names.
 * If the payload is a structured String like JSON or XML, use {@link Validator} or {@link StringValidator} instead.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public interface StringValidator extends Validator<String> {

    default Charset getCharset() {
        return charset;
    }

    default Function<byte[], String> getTransformer() {
        return bytes -> new String(bytes, getCharset());
    }

}