package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.cipherTransformation;
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
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64.Encoder;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
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
     * @param concatenatedKeys
     *            an array of 32 bytes of which the first 16 is the signing key and the last 16 is the
     *            encryption/decryption key
     */
    protected Key(final byte[] concatenatedKeys) {
        this(copyOfRange(concatenatedKeys, 0, signingKeyBytes),
                copyOfRange(concatenatedKeys, signingKeyBytes, fernetKeyBytes));
    }

    /**
     * @param string
     *            a Base 64 URL string in the format Signing-key (128 bits) || Encryption-key (128 bits)
     */
    public Key(final String string) {
        this(decoder.decode(string));
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
     *            the encrypted content of the token
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
    protected SecretKeySpec getEncryptionKeySpec() {
        return new SecretKeySpec(getEncryptionKey(), getEncryptionAlgorithm());
    }

    public byte[] encrypt(final byte[] payload, final IvParameterSpec initializationVector) {
        try {
            final Cipher cipher = Cipher.getInstance(cipherTransformation);
            cipher.init(ENCRYPT_MODE, getEncryptionKeySpec(), initializationVector);
            return cipher.doFinal(payload);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            // these should not happen as we use an algorithm (AES) and padding (PKCS5) that are guaranteed to exist
            throw new RuntimeException("Unable to access cipher: " + e.getMessage(), e);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
            // this should not happen as the key is validated ahead of time and
            // we use an algorithm guaranteed to exist
            throw new RuntimeException("Unable to initialise cipher: " + e.getMessage(), e);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            // these should not happen as we control the block size and padding
            throw new RuntimeException("Unable to encrypt data: " + e.getMessage(), e);
        }
    }

    public byte[] decrypt(final byte[] cipherText, final IvParameterSpec initializationVector) {
        try {
            final Cipher cipher = Cipher.getInstance(getCipherTransformation());
            cipher.init(DECRYPT_MODE, getEncryptionKeySpec(), initializationVector);
            return cipher.doFinal(cipherText);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            // this should not happen as we use an algorithm (AES) and padding
            // (PKCS5) that are guaranteed to exist.
            throw new RuntimeException(e.getMessage(), e);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            // these should not happen due to upfront validation
            throw new RuntimeException(e.getMessage(), e);
        } catch (final BadPaddingException bpe) {
            throw new TokenValidationException("Invalid padding in token: " + bpe.getMessage(), bpe);
        }
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

    protected String getCipherTransformation() {
        return cipherTransformation;
    }

}