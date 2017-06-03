package com.macasaet.fernet;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Fernet {

	private static final Charset charset = Charset.forName("UTF-8");
	private static final Encoder encoder = Base64.getUrlEncoder().withoutPadding();
	private static final Decoder decoder = Base64.getUrlDecoder();
	private static final String encryptionAlgorithm = "AES";
	private static final String signingAlgorithm = "HmacSHA256";

	public static class Key {

		private final byte[] signingKey;
		private final byte[] encryptionKey;

		public Key(final byte[] signingKey, final byte[] encryptionKey) {
			if (signingKey == null || signingKey.length != 16) {
				throw new IllegalArgumentException("Signing key must be 128 bits");
			}
			if (encryptionKey == null || encryptionKey.length != 16) {
				throw new IllegalArgumentException("Encryption key must be 128 bits");
			}
			this.signingKey = signingKey;
			this.encryptionKey = encryptionKey;
		}

		public static Key fromString(final String string) {
			final byte[] bytes = decoder.decode(string);
			final byte[] signingKey = Arrays.copyOfRange(bytes, 0, 16);
			final byte[] encryptionKey = Arrays.copyOfRange(bytes, 16, 32);
			return new Key(signingKey, encryptionKey);
		}

		public byte[] getSigningKey() {
			return signingKey;
		}

		public byte[] getEncryptionKey() {
			return encryptionKey;
		}

		public SecretKeySpec getSigningKeySpec() {
			return new SecretKeySpec(getSigningKey(), signingAlgorithm);
		}

		public SecretKeySpec getEncryptionKeySpec() {
			return new SecretKeySpec(getEncryptionKey(), encryptionAlgorithm);
		}

		public String serialise() {
			try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(16 + 16)) {
				byteStream.write(getSigningKey());
				byteStream.write(getEncryptionKey());
				return getEncoder().encodeToString(byteStream.toByteArray());
			} catch (final IOException ioe) {
				throw new RuntimeException(ioe.getMessage(), ioe);
			}
		}

		public byte[] getHmac(final byte version, final long timestamp, final IvParameterSpec initializationVector, final byte[] cipherText) {
			try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1 + 8 + 16 + cipherText.length)) {
				try (final DataOutputStream dataStream = new DataOutputStream(byteStream)) {
					dataStream.writeByte(version);
					dataStream.writeLong(timestamp);
					dataStream.write(initializationVector.getIV());
					dataStream.write(cipherText);
					dataStream.flush();

					try {
						final Mac mac = Mac.getInstance(signingAlgorithm);
						try {
							mac.init(getSigningKeySpec());
							return mac.doFinal(byteStream.toByteArray());
						} catch (final InvalidKeyException ike) {
							throw new RuntimeException(ike.getMessage(), ike);
						}
					} catch (final NoSuchAlgorithmException nsae) {
						// this should not happen as implementors are required to provide the HmacSHA256 algorithm.
						throw new RuntimeException(nsae.getMessage(), nsae);
					}
				}
			} catch (final IOException e) {
				// this should not happen as IO is to memory only
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		protected Encoder getEncoder() {
			return encoder;
		}
	}

	public static class Token {

		private final byte version;
		private final long timestamp;
		private final IvParameterSpec initializationVector;
		private final byte[] cipherText;
		private final byte[] hmac;

		protected Token(final byte version, final long timestamp, final IvParameterSpec initializationVector, final byte[] cipherText, final byte[] hmac) {
			if (version != (byte)0x80) {
				throw new IllegalArgumentException("Unsupported version: " + version);
			}
			if (initializationVector == null || initializationVector.getIV().length != 16) {
				throw new IllegalArgumentException("Initialization Vector must be 128 bits");
			}
			if (cipherText == null || cipherText.length % 16 != 0) {
				throw new IllegalArgumentException("Ciphertext must be a multiple of 128 bits");
			}
			if( hmac == null || hmac.length != 32) {
				throw new IllegalArgumentException("hmac must be 256 bits");
			}
			this.version = version;
			this.timestamp = timestamp;
			this.initializationVector = initializationVector;
			this.cipherText = cipherText;
			this.hmac = hmac;
		}

		protected static Token fromBytes(final byte[] bytes) {
			if( bytes.length < 1 + 8 + 16 + 32 ) {
				throw new IllegalArgumentException("Not enough bits to generate a Token");
			}
			try (final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes)) {
				final DataInputStream dataStream = new DataInputStream(inputStream);
				final byte version = dataStream.readByte();
				final long timestamp = dataStream.readLong();
				final byte[] initializationVectorBytes = new byte[16];
				final int ivBytesRead = dataStream.read(initializationVectorBytes);
				if (ivBytesRead < 16) {
					throw new IllegalArgumentException("Not enough bits to generate a Token");
				}
				final byte[] cipherText = new byte[bytes.length - 1 - 8 - 16 - 32];
				final int cipherTextBytesRead = dataStream.read(cipherText);
				if (cipherTextBytesRead < 16) {
					throw new IllegalArgumentException("Not enough bits to generate a Token");
				}
				final byte[] hmac = new byte[32];
				final int hmacBytesRead = dataStream.read(hmac);
				if( hmacBytesRead < 32) {
					throw new IllegalArgumentException("not enough bits to generate a Token");
				}
				return new Token(version, timestamp, new IvParameterSpec(initializationVectorBytes), cipherText, hmac);
			} catch (final IOException ioe) {
				throw new RuntimeException(ioe.getMessage(), ioe);
			}
		}

		public static Token fromString(final String string) {
			return fromBytes(decoder.decode(string));
		}

		public Token(final IvParameterSpec initializationVector, final byte[] cipherText, final byte[] hmac) {
			this((byte) 0x80, TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()), initializationVector,
					cipherText, hmac);
		}

		public Token(final Random random, final byte[] cipherText, final byte[] hmac) {
			this(generateInitializationVector(random), cipherText, hmac);
		}

		protected static IvParameterSpec generateInitializationVector(final Random random) {
			return new IvParameterSpec(generateInitializationVectorBytes(random));
		}

		protected static byte[] generateInitializationVectorBytes(final Random random) {
			final byte[] retval = new byte[16];
			random.nextBytes(retval);
			return retval;
		}

		public static Token generate(final Random random, final Key key, final String plainText)
				throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
				InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
			final IvParameterSpec initializationVector = generateInitializationVector(random);
			final byte[] cipherText = encrypt(key, plainText, initializationVector);
			final byte[] hmac = key.getHmac((byte)0x80, System.currentTimeMillis(), initializationVector, cipherText);
			return new Token(initializationVector, cipherText, hmac);
		}

		protected static byte[] encrypt(final Key key, final String string, final IvParameterSpec initializationVector) {
			try {
				final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				return encrypt(key, cipher, string, initializationVector);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				// this should not happen
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		protected static byte[] encrypt(final Key key, final Cipher cipher, final String string,
				final IvParameterSpec initializationVector) {
			try {
				cipher.init(ENCRYPT_MODE, key.getEncryptionKeySpec(), initializationVector);
				return cipher.doFinal(string.getBytes(charset));
			} catch (final InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
					| BadPaddingException e) {
				// this should not happen
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		public boolean isValid(final Key key, final long earliestValidTimestamp, final long latestValidTimestamp) {
			return isValidVersion()
					&& isNotExpired(earliestValidTimestamp)
					&& isNotTooFarInTheFuture(latestValidTimestamp)
					&& isValidSignature(key);
		}

		protected boolean isValidSignature(final Key key) {
			final byte[] computedHmac = key.getHmac(getVersion(), getTimestamp(), getInitializationVector(),
					getCipherText());
			return Arrays.equals(getHmac(), computedHmac);
		}

		protected boolean isNotTooFarInTheFuture(final long latestValidTimestamp) {
			return getTimestamp() <= latestValidTimestamp;
		}

		protected boolean isNotExpired(final long earliestValidTimestamp) {
			return getTimestamp() >= earliestValidTimestamp;
		}

		protected boolean isValidVersion() {
			return getVersion() == (byte) 0x80;
		}

		protected String decrypt(final Cipher cipher, final Key key) {
			try {
				cipher.init(DECRYPT_MODE, key.getEncryptionKeySpec(), getInitializationVector());
				final byte[] plainBytes = cipher.doFinal(getCipherText());
				return new String(plainBytes, charset);
			} catch (final InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		public String decrypt(final Key key) {
			try {
				final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				return decrypt(cipher, key);
			} catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
				// this should not happen
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		public String getTokenString() {
			try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(
					1 + 8 + 16 + getCipherText().length + 32)) {
				try (final DataOutputStream dataStream = new DataOutputStream(byteStream)) {
					dataStream.writeByte(getVersion());
					dataStream.writeLong(getTimestamp());
					dataStream.write(getInitializationVector().getIV());
					dataStream.write(getCipherText());
					dataStream.write(getHmac());
					dataStream.flush();

					return encoder.encodeToString(byteStream.toByteArray());
				}
			} catch (final IOException e) {
				// this should not happen as IO is to memory only
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		public byte getVersion() {
			return version;
		}

		public long getTimestamp() {
			return timestamp;
		}

		public IvParameterSpec getInitializationVector() {
			return initializationVector;
		}

		public byte[] getCipherText() {
			return cipherText;
		}

		public byte[] getHmac() {
			return hmac;
		}

		public String toString() {
			final StringBuilder builder = new StringBuilder();
			builder.append("Token [version=").append(String.format("0x%x", new BigInteger(1, new byte[] { getVersion() })))
					.append(", timestamp=").append(Instant.ofEpochSecond(getTimestamp()))
					.append(", initializationVector=").append(encoder.encodeToString(getInitializationVector().getIV()))
					.append(", cipherText=").append(encoder.encodeToString(getCipherText()))
					.append(", hmac=").append(encoder.encodeToString(getHmac())).append("]");
			return builder.toString();
		}

	}
}