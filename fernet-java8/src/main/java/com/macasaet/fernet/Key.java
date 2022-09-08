/**
   Copyright 2017 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64.Encoder;

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
@SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods", "PMD.GodClass"})
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
    public Key(final byte[] signingKey, final byte[] encryptionKey) {
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
     * Create a Key from a payload containing the signing and encryption
     * key.
     *
     * @param concatenatedKeys an array of 32 bytes of which the first 16 is
     *                         the signing key and the last 16 is the
     *                         encryption/decryption key
     */
    public Key(final byte[] concatenatedKeys) {
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
     * @return a new shared secret key
     */
    public static Key generateKey() {
        return generateKey(new SecureRandom());
    }

    /**
     * Generate a random key
     *
     * @param random
     *            source of entropy
     * @return a new shared secret key
     */
    public static Key generateKey(final SecureRandom random) {
        final byte[] signingKey = new byte[signingKeyBytes];
        random.nextBytes(signingKey);
        final byte[] encryptionKey = new byte[encryptionKeyBytes];
        random.nextBytes(encryptionKey);
        return new Key(signingKey, encryptionKey);
    }

    /**
     * Generate an HMAC SHA-256 signature from the components of a Fernet token.
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
    public byte[] sign(final byte version, final Instant timestamp, final IvParameterSpec initializationVector,
            final byte[] cipherText) {
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream(
                getTokenPrefixBytes() + cipherText.length)) {
            return sign(version, timestamp, initializationVector, cipherText, byteStream);
        } catch (final IOException e) {
            // this should not happen as I/O is to memory only
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /**
     * Encrypt a payload to embed in a Fernet token
     *
     * @param payload the raw bytes of the data to store in a token
     * @param initializationVector random bytes from a high-entropy source to initialise the AES cipher
     * @return the AES-encrypted payload. The length will always be a multiple of 16 (128 bits).
     * @see #decrypt(byte[], IvParameterSpec)
     */
    @SuppressWarnings("PMD.LawOfDemeter")
    public byte[] encrypt(final byte[] payload, final IvParameterSpec initializationVector) {
        final SecretKeySpec encryptionKeySpec = getEncryptionKeySpec();
        try {
            final Cipher cipher = Cipher.getInstance(cipherTransformation);
            cipher.init(ENCRYPT_MODE, encryptionKeySpec, initializationVector);
            return cipher.doFinal(payload);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            // these should not happen as we use an algorithm (AES) and padding (PKCS5) that are guaranteed to exist
            throw new IllegalStateException("Unable to access cipher " + cipherTransformation + ": " + e.getMessage(), e);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
            // this should not happen as the key is validated ahead of time and
            // we use an algorithm guaranteed to exist
            throw new IllegalStateException(
                    "Unable to initialise encryption cipher with algorithm " + encryptionKeySpec.getAlgorithm()
                            + " and format " + encryptionKeySpec.getFormat() + ": " + e.getMessage(),
                    e);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
            // these should not happen as we control the block size and padding
            throw new IllegalStateException("Unable to encrypt data: " + e.getMessage(), e);
        }
    }

    /**
     * <p>Decrypt the payload of a Fernet token.</p>
     *
     * <p>Warning: Do not call this unless the cipher text has first been verified. Attempting to decrypt a cipher text
     * that has been tampered with will leak whether or not the padding is correct and this can be used to decrypt
     * stolen cipher text.</p>
     *
     * @param cipherText
     *            the verified padded encrypted payload of a token. The length <em>must</em> be a multiple of 16 (128
     *            bits).
     * @param initializationVector
     *            the random bytes used in the AES encryption of the token
     * @return the decrypted payload
     * @see Key#encrypt(byte[], IvParameterSpec)
     */
    @SuppressWarnings("PMD.LawOfDemeter")
    protected byte[] decrypt(final byte[] cipherText, final IvParameterSpec initializationVector) {
        try {
            final Cipher cipher = Cipher.getInstance(getCipherTransformation());
            cipher.init(DECRYPT_MODE, getEncryptionKeySpec(), initializationVector);
            return cipher.doFinal(cipherText);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            // this should not happen as we use an algorithm (AES) and padding
            // (PKCS5) that are guaranteed to exist.
            // in addition, we validate the encryption key and initialization vector up front
            throw new IllegalStateException(e.getMessage(), e);
        } catch (final BadPaddingException bpe) {
            throw new TokenValidationException("Invalid padding in token: " + bpe.getMessage(), bpe);
        }
    }

    /**
     * @return the Base 64 URL representation of this Fernet key
     */
    @SuppressWarnings("PMD.LawOfDemeter")
    public String serialise() {
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream(fernetKeyBytes)) {
            writeTo(byteStream);
            return getEncoder().encodeToString(byteStream.toByteArray());
        } catch (final IOException ioe) {
            // this should not happen as I/O is to memory
            throw new IllegalStateException(ioe.getMessage(), ioe);
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

    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(getSigningKey());
        result = prime * result + Arrays.hashCode(getEncryptionKey());
        return result;
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Key)) {
            return false;
        }
        final Key other = (Key) obj;

        return MessageDigest.isEqual(getSigningKey(), other.getSigningKey())
                && MessageDigest.isEqual(getEncryptionKey(), other.getEncryptionKey());
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    protected byte[] sign(final byte version, final Instant timestamp, final IvParameterSpec initializationVector,
            final byte[] cipherText, final ByteArrayOutputStream byteStream)
        throws IOException {
        try (DataOutputStream dataStream = new DataOutputStream(byteStream)) {
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
                throw new IllegalStateException("Unable to initialise HMAC with shared secret: " + ike.getMessage(),
                        ike);
            } catch (final NoSuchAlgorithmException nsae) {
                // this should not happen as implementors are required to
                // provide the HmacSHA256 algorithm.
                throw new IllegalStateException(nsae.getMessage(), nsae);
            }
        }
    }

    /**
     * @return an HMAC SHA-256 key for signing the token
     */
    protected java.security.Key getSigningKeySpec() {
        return new SecretKeySpec(getSigningKey(), getSigningAlgorithm());
    }

    /**
     * @return the AES key for encrypting and decrypting the token payload
     */
    protected SecretKeySpec getEncryptionKeySpec() {
        return new SecretKeySpec(getEncryptionKey(), getEncryptionAlgorithm());
    }

    /**
     * Warning: Modifying the returned byte array will write through to this object.
     *
     * @return the raw underlying signing key bytes
     */
    @SuppressWarnings("PMD.MethodReturnsInternalArray")
    protected byte[] getSigningKey() {
        return signingKey;
    }

    /**
     * Warning: Modifying the returned byte array will write through to this object.
     *
     * @return the raw underlying encryption key bytes
     */
    @SuppressWarnings("PMD.MethodReturnsInternalArray")
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