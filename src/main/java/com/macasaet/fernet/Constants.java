package com.macasaet.fernet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

import java.nio.charset.Charset;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;

interface Constants {

	static final Charset charset = UTF_8;
	static final Encoder encoder = getUrlEncoder();
	static final Decoder decoder = getUrlDecoder();
	/**
	 * The algorithm used to encrypt the token contents.
	 */
	static final String encryptionAlgorithm = "AES";
	/**
	 * The algorithm used to sign the token.
	 */
	static final String signingAlgorithm = "HmacSHA256";
	/**
	 * The number of bytes used to store the encryption initialisation vector
	 */
	static final int initializationVectorBytes = 16;
	/**
	 * The number of bytes used to store the timestamp of a Fernet token. 
	 */
	static final int timestampBytes = 8;
	/**
	 * The number of bytes used to indicate the version of a Fernet token.
	 */
	static final int versionBytes = 1;
	/**
	 * The number of bytes before the cipher text portion of a Fernet token.
	 */
	static final int tokenPrefixBytes = versionBytes + timestampBytes + initializationVectorBytes;
	/**
	 * The number of bytes in a valid signing key.
	 */
	static final int signingKeyBytes = 16;
	/**
	 * The number of bytes in a valid encryption key.
	 */
	static final int encryptionKeyBytes = 16;
	/**
	 * The total number of bytes in a valid Fernet key.
	 */
	static final int fernetKeyBytes = signingKeyBytes + encryptionKeyBytes;
	/**
	 * The AES block size used by the cipher.
	 */
	static final int cipherTextBlockSize = 16;
	/**
	 * The transformation (algorithm, mode, and padding) used by the cipher.
	 * @see Cipher#getInstance(String)
	 */
	static final String cipherTransformation = encryptionAlgorithm + "/CBC/PKCS5Padding";
	/**
	 * The number of bytes for the HMAC signature.
	 */
	static final int signatureBytes = 32;
	/**
	 * The Fernet token version supported by this library.
	 */
	static final byte supportedVersion = (byte)0x80;
	/**
	 * The minimum number of bytes in a token.
	 */
	static final int tokenStaticBytes = versionBytes + timestampBytes + initializationVectorBytes + signatureBytes;

}