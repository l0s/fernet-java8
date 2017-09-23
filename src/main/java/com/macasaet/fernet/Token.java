package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.charset;
import static com.macasaet.fernet.Constants.cipherTextBlockSize;
import static com.macasaet.fernet.Constants.decoder;
import static com.macasaet.fernet.Constants.encoder;
import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static com.macasaet.fernet.Constants.minimumTokenBytes;
import static com.macasaet.fernet.Constants.signatureBytes;
import static com.macasaet.fernet.Constants.supportedVersion;
import static com.macasaet.fernet.Constants.tokenStaticBytes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64.Encoder;
import java.util.Collection;
import java.util.Random;

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
        if (timestamp == null) {
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

            final byte[] initializationVector = read(dataStream, initializationVectorBytes);
            final byte[] cipherText = read(dataStream, bytes.length - tokenStaticBytes);
            final byte[] hmac = read(dataStream, signatureBytes);

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

    protected static byte[] read(final DataInputStream stream, final int numBytes) throws IOException {
        final byte[] retval = new byte[numBytes];
        final int bytesRead = stream.read(retval);
        if (bytesRead < numBytes) {
            throw new IllegalTokenException("Not enough bits to generate a Token");
        }
        return retval;
    }

    /**
     * Deserialise a Base64 URL Fernet token string. This does NOT validate that the token was generated using a valid {@link Key}.
     *
     * @param string
     *            the Base 64 URL encoding of a token in the form Version | Timestamp | IV | Ciphertext | HMAC
     * @return a new Token
     * @throws IllegalTokenException
     *             if the input string cannot be a valid token irrespective of key or timestamp
     */
    public static Token fromString(final String string) throws IllegalTokenException {
        return fromBytes(decoder.decode(string));
    }

    /**
     * Convenience method to generate a new Fernet token with a string payload.
     *
     * @param random a source of entropy for your application
     * @param key the secret key for encrypting <em>plainText</em> and signing the token
     * @param plainText the payload to embed in the token
     * @return a unique Fernet token
     */
    public static Token generate(final Random random, final Key key, final String plainText) {
        return generate(random, key, plainText.getBytes(charset));
    }

    /**
     * Generate a new Fernet token.
     *
     * @param random a source of entropy for your application
     * @param key the secret key for encrypting <em>payload</em> and signing the token
     * @param payload the unencrypted data to embed in the token
     * @return a unique Fernet token
     */
    public static Token generate(final Random random, final Key key, final byte[] payload) {
        final IvParameterSpec initializationVector = generateInitializationVector(random);
        final byte[] cipherText = key.encrypt(payload, initializationVector);
        final Instant timestamp = Instant.now();
        final byte[] hmac = key.sign(supportedVersion, timestamp, initializationVector, cipherText);
        return new Token(supportedVersion, timestamp, initializationVector, cipherText, hmac);
    }

    /**
     * Check the validity of this token. 
     *
     * @param key the secret key against which to validate the token
     * @param validator an object that encapsulates the validation parameters (e.g. TTL)
     * @return the decrypted, deserialised payload of this token
     * @throws TokenValidationException if <em>key</em> was NOT used to generate this token
     */
    public <T> T validateAndDecrypt(final Key key, final Validator<T> validator) throws TokenValidationException {
        return validator.validateAndDecrypt(key, this);
    }

    /**
     * Check the validity of this token against a collection of keys. Use this if you have implemented key rotation.
     *
     * @param keys the active keys which may have been used to generate token
     * @param validator an object that encapsulates the validation parameters (e.g. TTL)
     * @return the decrypted, deserialised payload of this token
     * @throws TokenValidationException if none of the keys were used to generate this token
     */
    public <T> T validateAndDecrypt(final Collection<? extends Key> keys, final Validator<T> validator)
        throws TokenValidationException {
        return validator.validateAndDecrypt(keys, this);
    }

    protected byte[] validateAndDecrypt(final Key key, final Instant earliestValidInstant,
            final Instant latestValidInstant) throws TokenValidationException {
        if (getVersion() != (byte) 0x80) {
            throw new TokenValidationException("Invalid version");
        } else if (!getTimestamp().isAfter(earliestValidInstant)) {
            throw new TokenValidationException("Token is expired");
        } else if (!getTimestamp().isBefore(latestValidInstant)) {
            throw new TokenValidationException("Token timestamp is in the future (clock skew).");
        } else if (!isValidSignature(key)) {
            throw new TokenValidationException("Signature does not match.");
        }
        return key.decrypt(getCipherText(), getInitializationVector());
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
     * @param outputStream
     *            the target
     * @throws IOException
     *             if data cannot be written to the underlying stream
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
        builder.append("Token [version=").append(String.format("0x%x", new BigInteger(1, new byte[] {getVersion()})))
                .append(", timestamp=").append(getTimestamp())
                .append(", hmac=").append(encoder.encodeToString(getHmac())).append("]");
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

    /**
     * Recompute the HMAC signature of the token with the stored shared secret key.
     *
     * @param key
     *            the shared secret key against which to validate the token
     * @return true if and only if the signature on the token was generated using the supplied key
     */
    public boolean isValidSignature(final Key key) {
        final byte[] computedHmac = key.sign(getVersion(), getTimestamp(), getInitializationVector(),
                getCipherText());
        return Arrays.equals(getHmac(), computedHmac);
    }

    protected Encoder getEncoder() {
        return encoder;
    }

    protected byte[] getCipherText() {
        return cipherText;
    }

    /**
     * @return the HMAC 256 signature of this token
     */
    protected byte[] getHmac() {
        return hmac;
    }

}