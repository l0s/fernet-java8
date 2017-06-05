package com.macasaet.fernet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

import java.nio.charset.Charset;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

interface FernetConstants {

	static final Charset charset = UTF_8;
	static final Encoder encoder = getUrlEncoder().withoutPadding();
	static final Decoder decoder = getUrlDecoder();
	static final String encryptionAlgorithm = "AES";
	static final String signingAlgorithm = "HmacSHA256";
	static final int initializationVectorBytes = 16;
	static final int timestampBytes = 8;
	static final int versionBytes = 1;
	static final int tokenPrefixBytes = versionBytes + timestampBytes + initializationVectorBytes;
	static final int signingKeyBytes = 16;
	static final int encryptionKeyBytes = 16;
	static final int fernetKeyBytes = signingKeyBytes + encryptionKeyBytes;

}