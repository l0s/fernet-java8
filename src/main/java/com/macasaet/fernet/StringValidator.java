package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;

import java.nio.charset.Charset;
import java.util.function.Function;

public interface StringValidator extends Validator<String> {

    default Charset getCharset() {
        return charset;
    }

    default Function<byte[], String> getTransformer() {
        return bytes -> new String(bytes, getCharset());
    }

}