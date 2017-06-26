package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;

import java.nio.charset.Charset;
import java.util.function.Function;

public interface StringObjectValidator<T> extends Validator<T> {

    default Charset getCharset() {
        return charset;
    }

    default Function<byte[], String> getStringCreator() {
        return bytes -> new String(bytes, getCharset());
    }

    default Function<byte[], T> getTransformer() {
        return getStringCreator().andThen(getStringTransformer());
    }

    Function<String, T> getStringTransformer();

}