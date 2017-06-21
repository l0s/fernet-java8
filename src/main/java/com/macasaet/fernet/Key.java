package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.decoder;
import static com.macasaet.fernet.Constants.encoder;
import static com.macasaet.fernet.Constants.encryptionAlgorithm;
import static com.macasaet.fernet.Constants.encryptionKeyBytes;
import static com.macasaet.fernet.Constants.fernetKeyBytes;
import static com.macasaet.fernet.Constants.signingAlgorithm;
import static com.macasaet.fernet.Constants.signingKeyBytes;
import static com.macasaet.fernet.Constants.tokenPrefixBytes;
import static java.util.Arrays.copyOf;
import static java.util.Arrays.copyOfRange;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64.Encoder;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A Fernet shared secret key.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Key {

    private final byte[] signingKey;
    private final byte[] encryptionKey;

    /**
     * Create a Key from individual components.
     *
     * @param signingKey
     *            a 128-bit (16 byte) key for signing tokens.
     * @param encryptionKey
     *            a 128-bit (16 byte) key for encrypting and decrypting token contents.
     */
    protected Key(final byte[] signingKey, final byte[] encryptionKey) {
        if (signingKey == null || signingKey.length != signingKeyBytes) {
            throw new IllegalArgumentException("Signing key must be 128 bits");
        }
        if (encryptionKey == null || encryptionKey.length != encryptionKeyBytes) {
            throw new IllegalArgumentException("Encryption key must be 128 bits");
        }
        this.signingKey = copyOf(signingKey, signingKeyBytes);
        this.encryptionKey = copyOf(encryptionKey, encryptionKeyBytes);
    }

    /**
     * @param string
     *            a Base 64 URL string in the format Signing-key (128 bits) || Encryption-key (128 bits)
     * @return a Fernet key from the specification
     */
    public static Key fromString(final String string) {
        final byte[] bytes = decoder.decode(string);
        final byte[] signingKey = copyOfRange(bytes, 0, signingKeyBytes);
        final byte[] encryptionKey = copyOfRange(bytes, signingKeyBytes, fernetKeyBytes);
        return new Key(signingKey, encryptionKey);
    }

    /**
     * Generate a random key
     *
     * @param random
     *            source of entropy
     * @return a new shared secret key
     */
    public static Key generateKey(final Random random) {
        final byte[] signingKey = new byte[signingKeyBytes];
        random.nextBytes(signingKey);
        final byte[] encryptionKey = new byte[encryptionKeyBytes];
        random.nextBytes(encryptionKey);
        return new Key(signingKey, encryptionKey);
    }

    /**
     * Generate an HMAC signature from the components of a Fernet token.
     *
     * @param version
     *            the Fernet version number
     * @param timestamp
     *            the seconds after the epoch that the token was generated
     * @param initializationVector
     *            the encryption and decryption initialization vector
     * @param cipherText
     *            the encrypted content of the token // FIXME not thread safe
     * @return the HMAC signature
     */
    public byte[] getHmac(final byte version, final Instant timestamp, final IvParameterSpec initializationVector,
            final byte[] cipherText) {
        try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(
                getTokenPrefixBytes() + cipherText.length)) {
            try (final DataOutputStream dataStream = new DataOutputStream(byteStream)) {
                dataStream.writeByte(version);
                dataStream.writeLong(timestamp.getEpochSecond());
                dataStream.write(initializationVector.getIV());
                dataStream.write(cipherText);

                try {
                    final Mac mac = Mac.getInstance(getSigningAlgorithm());
                    mac.init(getSigningKeySpec());
                    return mac.doFinal(byteStream.toByteArray());
                } catch (final InvalidKeyException ike) {
                    // this should not happen because we control the signing key
                    // algorithm and pre-validate the length
                    throw new RuntimeException("Unable to initialise HMAC with shared secret: " + ike.getMessage(),
                            ike);
                } catch (final NoSuchAlgorithmException nsae) {
                    // this should not happen as implementors are required to
                    // provide the HmacSHA256 algorithm.
                    throw new RuntimeException(nsae.getMessage(), nsae);
                }
            }
        } catch (final IOException e) {
            // this should not happen as I/O is to memory only
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * @return an HMAC key for signing the token
     */
    public SecretKeySpec getSigningKeySpec() {
        return new SecretKeySpec(getSigningKey(), getSigningAlgorithm());
    }

    /**
     * @return the key for encrypting and decrypting the token payload
     */
    public SecretKeySpec getEncryptionKeySpec() {
        return new SecretKeySpec(getEncryptionKey(), getEncryptionAlgorithm());
    }

    /**
     * @return the Base 64 URL representation of this Fernet key
     */
    public String serialise() {
        try (final ByteArrayOutputStream byteStream = new ByteArrayOutputStream(fernetKeyBytes)) {
            writeTo(byteStream);
            return getEncoder().encodeToString(byteStream.toByteArray());
        } catch (final IOException ioe) {
            // this should not happen as I/O is to memory
            throw new RuntimeException(ioe.getMessage(), ioe);
        }
    }

    /**
     * Write the raw bytes of this key to the specified output stream.
     *
     * @param outputStream
     *            the target
     * @throws IOException
     *             if the underlying I/O device cannot be written to
     */
    public void writeTo(final OutputStream outputStream) throws IOException {
        outputStream.write(getSigningKey());
        outputStream.write(getEncryptionKey());
    }

    protected byte[] getSigningKey() {
        return signingKey;
    }

    protected byte[] getEncryptionKey() {
        return encryptionKey;
    }

    protected int getTokenPrefixBytes() {
        return tokenPrefixBytes;
    }

    protected String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    protected String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    protected Encoder getEncoder() {
        return encoder;
    }

}