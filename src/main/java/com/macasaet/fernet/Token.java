package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;
import static com.macasaet.fernet.Constants.cipherTextBlockSize;
import static com.macasaet.fernet.Constants.cipherTransformation;
import static com.macasaet.fernet.Constants.decoder;
import static com.macasaet.fernet.Constants.encoder;
import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static com.macasaet.fernet.Constants.signatureBytes;
import static com.macasaet.fernet.Constants.supportedVersion;
import static com.macasaet.fernet.Constants.tokenStaticBytes;
import static java.lang.System.currentTimeMillis;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64.Encoder;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * A Fernet token.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Token {

	private final byte version;
	private final long timestamp;
	private final IvParameterSpec initializationVector;
	private final byte[] cipherText;
	private final byte[] hmac;

	protected Token(final byte version, final long timestamp, final IvParameterSpec initializationVector,
			final byte[] cipherText, final byte[] hmac) {
		if (version != supportedVersion) {
			throw new InvalidTokenException("Unsupported version: " + version);
		}
		if (initializationVector == null || initializationVector.getIV().length != initializationVectorBytes) {
			throw new InvalidTokenException("Initialization Vector must be 128 bits");
		}
		if (cipherText == null || cipherText.length % cipherTextBlockSize != 0) {
			throw new InvalidTokenException("Ciphertext must be a multiple of 128 bits");
		}
		if (hmac == null || hmac.length != signatureBytes) {
			throw new InvalidTokenException("hmac must be 256 bits");
		}
		this.version = version;
		this.timestamp = timestamp;
		this.initializationVector = initializationVector;
		this.cipherText = cipherText;
		this.hmac = hmac;
	}

	// TODO fromBytes(final InputStream inputStream)

	protected static Token fromBytes(final byte[] bytes) throws InvalidTokenException {
		if (bytes.length < tokenStaticBytes) {
			throw new InvalidTokenException("Not enough bits to generate a Token");
		}
		try (final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes)) {
			final DataInputStream dataStream = new DataInputStream(inputStream);
			final byte version = dataStream.readByte();
			final long timestamp = dataStream.readLong();

			final byte[] initializationVector = new byte[initializationVectorBytes];
			final int ivBytesRead = dataStream.read(initializationVector);
			if (ivBytesRead < 16) {
				throw new InvalidTokenException("Not enough bits to generate a Token");
			}

			final byte[] cipherText = new byte[bytes.length - tokenStaticBytes];
			final int cipherTextBytesRead = dataStream.read(cipherText);
			if (cipherTextBytesRead < cipherText.length) {
				throw new InvalidTokenException("Not enough bits to generate a Token");
			}
			final int padLength = Byte.valueOf(cipherText[cipherText.length - 1]).intValue();
			if (padLength > cipherTextBlockSize) {
				throw new InvalidTokenException("Padding cannot exceed 16 bytes.");
			}

			final byte[] hmac = new byte[signatureBytes];
			final int hmacBytesRead = dataStream.read(hmac);
			if (hmacBytesRead < signatureBytes) {
				throw new InvalidTokenException("not enough bits to generate a Token");
			}

			if (dataStream.read() != -1) {
				throw new InvalidTokenException("more bits found");
			}
			return new Token(version, timestamp, new IvParameterSpec(initializationVector), cipherText, hmac);
		} catch (final IOException ioe) {
			// this should not happen as I/O is from memory and stream
			// length is verified ahead of time
			throw new RuntimeException(ioe.getMessage(), ioe);
		}
	}

	/**
	 * Deserialise a Base64 URL Fernet token string.
	 *
	 * @param string the Base 64 URL encoding of a token in the form Version | Timestamp | IV | Ciphertext | HMAC
	 * @return a new Token
	 * @throws InvalidTokenException if the input string cannot be a valid token irrespective of key or timestamp
	 */
	public static Token fromString(final String string) throws InvalidTokenException {
		return fromBytes(decoder.decode(string));
	}

	public static Token generate(final Random random, final Key key, final String plainText) {
		final IvParameterSpec initializationVector = generateInitializationVector(random);
		final byte[] cipherText = encrypt(key, plainText, initializationVector);
		final long timestamp = MILLISECONDS.toSeconds(currentTimeMillis());
		final byte[] hmac = key.getHmac(supportedVersion, timestamp, initializationVector, cipherText);
		return new Token(supportedVersion, timestamp, initializationVector, cipherText, hmac);
	}

	/**
	 * Validate the token. 
	 *
	 * TODO: refactor to accept instants
	 * 
	 * @param key stored shared secret key
	 * @param earliestValidTimestamp the earliest time for which tokens are valid
	 * @param latestValidTimestamp the latest time (in the future) for which tokens are valid.
	 * @return true if and only if the token was generated using the supplied key and is within the specified time bounds.
	 */
	@Deprecated
	public boolean isValid(final Key key, final long earliestValidTimestamp, final long latestValidTimestamp) {
		if (!isMostlyValid(key, earliestValidTimestamp, latestValidTimestamp)) {
			return false;
		}
		try {
			// validate the encryption
			final Cipher cipher = Cipher.getInstance(cipherTransformation);
			decrypt(cipher, key);
			return true;
		} catch (final BadPaddingException e) {
			return false;
		} catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
			// these should not happen as we use an algorithm (AES) and padding (PKCS5) that are guaranteed to exist
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	@Deprecated
	public String decrypt(final Key key) throws TokenValidationException {
		try {
			final Cipher cipher = Cipher.getInstance(getCipherTransformation());
			return decrypt(cipher, key);
		} catch (final BadPaddingException bpe) {
			throw new TokenValidationException("Invalid padding in token: " + bpe.getMessage(), bpe);
		} catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
			// this should not happen
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	// FIXME: refactor to accept Instants instead
	public String validateAndDecrypt(final Key key, final long earliestValidTimestamp,
			final long latestValidTimestamp) {
		// TODO I think this should be the primary validation method moving forward
		// TODO throw separate exceptions for each scenario
		if (!isMostlyValid(key, earliestValidTimestamp, latestValidTimestamp)) {
			throw new TokenValidationException("Invalid token");
		}
		return decrypt(key);
	}

	public String validateAndDecrypt(final Key key, final TokenValidator validator) throws TokenValidationException {
		return validator.validateAndDecrypt(key, this);
	}

	// TODO String validateAndDecrypt(Key, TemporalAmount, TemporalAmount, Predicate<String>)

	/**
	 * @return the Base 64 URL encoding of this token in the form Version | Timestamp | IV | Ciphertext | HMAC
	 */
	public String serialise() {
		try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(
				tokenStaticBytes + getCipherText().length)) {
			serialise(byteStream);
			return getEncoder().encodeToString(byteStream.toByteArray());
		} catch (final IOException e) {
			// this should not happen as IO is to memory only
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	public void serialise(final OutputStream outputStream) throws IOException {
		try (final DataOutputStream dataStream = new DataOutputStream(outputStream)) {
			dataStream.writeByte(getVersion());
			dataStream.writeLong(getTimestamp());
			dataStream.write(getInitializationVector().getIV());
			dataStream.write(getCipherText());
			dataStream.write(getHmac());
			dataStream.flush();
		}
	}

	public byte getVersion() {
		return version;
	}

	/**
	 * @return the number of seconds after the epoch that this token was generated
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * @return the initialisation vector used to encrypt the token contents 
	 */
	public IvParameterSpec getInitializationVector() {
		return initializationVector;
	}

	public String toString() {
		final StringBuilder builder = new StringBuilder();
		final byte[] ivBytes = getInitializationVector().getIV();
		builder.append("Token [version=").append(String.format("0x%x", new BigInteger(1, new byte[] { getVersion() })))
				.append(", timestamp=").append(toDateString(getTimestamp()))
				.append(", initializationVector=").append(toBase64String(ivBytes))
				.append(", cipherText=").append(Constants.encoder.encodeToString(getCipherText()))
				.append(", hmac=").append(Constants.encoder.encodeToString(getHmac())).append("]");
		return builder.toString();
	}

	protected static IvParameterSpec generateInitializationVector(final Random random) {
		return new IvParameterSpec(generateInitializationVectorBytes(random));
	}

	protected static byte[] generateInitializationVectorBytes(final Random random) {
		final byte[] retval = new byte[initializationVectorBytes];
		random.nextBytes(retval);
		return retval;
	}

	protected static byte[] encrypt(final Key key, final String string, final IvParameterSpec initializationVector) {
		try {
			final Cipher cipher = Cipher.getInstance(cipherTransformation);
			return encrypt(key, cipher, string, initializationVector);
		} catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
			// these should not happen as we use an algorithm (AES) and padding (PKCS5) that are guaranteed to exist
			throw new RuntimeException("Unable to access cipher: " + e.getMessage(), e);
		}
	}

	protected static byte[] encrypt(final Key key, final Cipher cipher, final String string,
			final IvParameterSpec initializationVector) {
		try {
			cipher.init(ENCRYPT_MODE, key.getEncryptionKeySpec(), initializationVector);
			return cipher.doFinal(string.getBytes(Constants.charset));
		} catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
			// this should not happen as the key is validated ahead of time and
			// we use an algorithm guaranteed to exist
			throw new RuntimeException("Unable to initialise cipher: " + e.getMessage(), e);
		} catch (final IllegalBlockSizeException | BadPaddingException e) {
			// these should not happen as we control the block size and padding
			throw new RuntimeException("Unable to encrypt data: " + e.getMessage(), e);
		}
	}

	protected boolean isMostlyValid(final Key key, final long earliestValidTimestamp, final long latestValidTimestamp) {
		return isValidVersion()
				&& isNotExpired(earliestValidTimestamp)
				&& isNotTooFarInTheFuture(latestValidTimestamp)
				&& isValidSignature(key);
	}

	/**
	 * Recompute the HMAC signature of the token with the stored shared secret key.
	 *
	 * @param key the shared secret key against which to validate the token
	 * @return true if and only if the signature on the token was generated using the supplied key
	 */
	protected boolean isValidSignature(final Key key) {
		final byte[] computedHmac = key.getHmac(getVersion(), getTimestamp(), getInitializationVector(),
				getCipherText());
		return Arrays.equals(getHmac(), computedHmac);
	}

	/**
	 * Evaluate whether or not any clock skew is acceptable.
	 *
	 * @param latestValidTimestamp the latest time that this token would be considered valid, expressed in seconds after the epoch
	 * @return true if and only if this token is not too far in the future
	 */
	protected boolean isNotTooFarInTheFuture(final long latestValidTimestamp) {
		return getTimestamp() <= latestValidTimestamp;
	}

	/**
	 * @param earliestValidTimestamp the earliest time that this token would be considered valid, expressed in seconds after the epoch.
	 * @return true if and only if this token is not expired
	 */
	protected boolean isNotExpired(final long earliestValidTimestamp) {
		return getTimestamp() >= earliestValidTimestamp;
	}

	/**
	 * @return true if and only if the token specifies a valid version
	 */
	protected boolean isValidVersion() {
		return getVersion() == (byte) 0x80;
	}

	protected String decrypt(final Cipher cipher, final Key key) throws BadPaddingException {
		try {
			cipher.init(DECRYPT_MODE, key.getEncryptionKeySpec(), getInitializationVector());
			final byte[] plainBytes = cipher.doFinal(getCipherText());
			return new String(plainBytes, charset);
		} catch (final InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
			// these should not happen due to upfront validation
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	protected String getCipherTransformation() {
		return cipherTransformation;
	}

	protected Encoder getEncoder() {
		return encoder;
	}

	protected byte[] getCipherText() {
		return cipherText;
	}

	protected byte[] getHmac() {
		return hmac;
	}

	protected static String toDateString(final long secondsSinceEpoch) {
		return Instant.ofEpochSecond(secondsSinceEpoch).toString();
	}

	protected static String toBase64String(final byte[] input) {
		return encoder.encodeToString(input);
	}

}