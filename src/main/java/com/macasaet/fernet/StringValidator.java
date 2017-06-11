package com.macasaet.fernet;

import java.util.function.Function;

public interface StringValidator extends Validator<String> {

	default Function<String, String> getTransformer() {
		return Function.identity();
	}

}