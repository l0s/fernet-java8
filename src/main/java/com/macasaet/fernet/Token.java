package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;
import static com.macasaet.fernet.Constants.cipherTextBlockSize;
import static com.macasaet.fernet.Constants.cipherTransformation;
import static com.macasaet.fernet.Constants.decoder;
import static com.macasaet.fernet.Constants.encoder;
import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static com.macasaet.fernet.Constants.minimumTokenBytes;
import static com.macasaet.fernet.Constants.signatureBytes;
import static com.macasaet.fernet.Constants.supportedVersion;
import static com.macasaet.fernet.Constants.tokenStaticBytes;
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
	private final Instant timestamp;
	private final IvParameterSpec initializationVector;
	private final byte[] cipherText;
	private final byte[] hmac;

	protected Token(final byte version, final Instant timestamp, final IvParameterSpec initializationVector,
			final byte[] cipherText, final byte[] hmac) {
		if (version != supportedVersion) {
			throw new IllegalTokenException("Unsupported version: " + version);
		}
		if( timestamp == null ) {
			throw new IllegalTokenException("timestamp cannot be null");
		}
		if (initializationVector == null || initializationVector.getIV().length != initializationVectorBytes) {
			throw new IllegalTokenException("Initialization Vector must be 128 bits");
		}
		if (cipherText == null || cipherText.length % cipherTextBlockSize != 0) {
			throw new IllegalTokenException("Ciphertext must be a multiple of 128 bits");
		}
		if (hmac == null || hmac.length != signatureBytes) {
			throw new IllegalTokenException("hmac must be 256 bits");
		}
		this.version = version;
		this.timestamp = timestamp;
		this.initializationVector = initializationVector;
		this.cipherText = cipherText;
		this.hmac = hmac;
	}

	protected static Token fromBytes(final byte[] bytes) throws IllegalTokenException {
		if (bytes.length < minimumTokenBytes) {
			throw new IllegalTokenException("Not enough bits to generate a Token");
		}
		try (final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes)) {
			final DataInputStream dataStream = new DataInputStream(inputStream);
			final byte version = dataStream.readByte();
			final long timestampSeconds = dataStream.readLong();

			final byte[] initializationVector = new byte[initializationVectorBytes];
			final int ivBytesRead = dataStream.read(initializationVector);
			if (ivBytesRead < initializationVectorBytes) {
				throw new IllegalTokenException("Not enough bits to generate a Token");
			}

			final byte[] cipherText = new byte[bytes.length - tokenStaticBytes];
			final int cipherTextBytesRead = dataStream.read(cipherText);
			if (cipherTextBytesRead < cipherText.length) {
				throw new IllegalTokenException("Not enough bits to generate a Token");
			}
			final int padLength = Byte.valueOf(cipherText[cipherText.length - 1]).intValue();
			if (padLength > cipherTextBlockSize) {
				throw new IllegalTokenException("Padding cannot exceed 16 bytes.");
			}

			final byte[] hmac = new byte[signatureBytes];
			final int hmacBytesRead = dataStream.read(hmac);
			if (hmacBytesRead < signatureBytes) {
				throw new IllegalTokenException("not enough bits to generate a Token");
			}

			if (dataStream.read() != -1) {
				throw new IllegalTokenException("more bits found");
			}
			return new Token(version, Instant.ofEpochSecond(timestampSeconds),
					new IvParameterSpec(initializationVector), cipherText, hmac);
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
	 * @throws IllegalTokenException if the input string cannot be a valid token irrespective of key or timestamp
	 */
	public static Token fromString(final String string) throws IllegalTokenException {
		return fromBytes(decoder.decode(string));
	}

	public static Token generate(final Random random, final Key key, final String plainText) {
		final IvParameterSpec initializationVector = generateInitializationVector(random);
		final byte[] cipherText = encrypt(key, plainText, initializationVector);
		final Instant timestamp = Instant.now();
		final byte[] hmac = key.getHmac(supportedVersion, timestamp, initializationVector, cipherText);
		return new Token(supportedVersion, timestamp, initializationVector, cipherText, hmac);
	}

	public <T> T validateAndDecrypt(final Key key, final Validator<T> validator) throws TokenValidationException {
		return validator.validateAndDecrypt(key, this);
	}

	public String validateAndDecrypt(final Key key, final Instant earliestValidInstant,
			final Instant latestValidInstant) {
		if (getVersion() != (byte) 0x80) {
			throw new TokenValidationException("Invalid version");
		} else if (!getTimestamp().isAfter(earliestValidInstant)) {
			throw new TokenValidationException("Token is expired");
		} else if (!getTimestamp().isBefore(latestValidInstant)) {
			throw new TokenValidationException("Token timestamp is in the future (clock skew).");
		} else if (!isValidSignature(key)) {
			throw new TokenValidationException("Signature does not match.");
		}

		try {
			final Cipher cipher = Cipher.getInstance(getCipherTransformation());
			return decrypt(cipher, key);
		} catch (final BadPaddingException bpe) {
			throw new TokenValidationException("Invalid padding in token: " + bpe.getMessage(), bpe);
		} catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
			// this should not happen as we use an algorithm (AES) and padding
			// (PKCS5) that are guaranteed to exist.
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	/**
	 * @return the Base 64 URL encoding of this token in the form Version | Timestamp | IV | Ciphertext | HMAC
	 */
	public String serialise() {
		try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(
				tokenStaticBytes + getCipherText().length)) {
			writeTo(byteStream);
			return getEncoder().encodeToString(byteStream.toByteArray());
		} catch (final IOException e) {
			// this should not happen as IO is to memory only
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	/**
	 * Write the raw bytes of this token to the specified output stream.
	 *
	 * @param outputStream the target
	 * @throws IOException if data cannot be written to the underlying stream
	 */
	public void writeTo(final OutputStream outputStream) throws IOException {
		try (final DataOutputStream dataStream = new DataOutputStream(outputStream)) {
			dataStream.writeByte(getVersion());
			dataStream.writeLong(getTimestamp().getEpochSecond());
			dataStream.write(getInitializationVector().getIV());
			dataStream.write(getCipherText());
			dataStream.write(getHmac());
		}
	}

	/**
	 * @return the Fernet specification version of this token
	 */
	public byte getVersion() {
		return version;
	}

	/**
	 * @return the time that this token was generated
	 */
	public Instant getTimestamp() {
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
				.append(", timestamp=").append(getTimestamp())
				.append(", initializationVector=").append(encoder.encodeToString(ivBytes))
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

	/**
	 * Recompute the HMAC signature of the token with the stored shared secret key.
	 *
	 * @param key the shared secret key against which to validate the token
	 * @return true if and only if the signature on the token was generated using the supplied key
	 */
	protected boolean isValidSignature(final Key key) {
		final byte[] computedHmac =
				key.getHmac(getVersion(), getTimestamp(), getInitializationVector(), getCipherText());
		return Arrays.equals(getHmac(), computedHmac);
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

}