package com.macasaet.fernet;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.oneOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeThat;

import java.time.Instant;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import org.junit.runner.RunWith;

import com.macasaet.fernet.property.CipherBytesGenerator;
import com.macasaet.fernet.property.IvGenerator;
import com.macasaet.fernet.property.KeyGenerator;
import com.macasaet.fernet.property.PlainBytesGenerator;
import com.pholser.junit.quickcheck.From;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.InRange;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;

@RunWith(JUnitQuickcheck.class)
public class KeyProperties {

    @Property
    public final void signaturesForSameParametersAndKeyMatch(@From(KeyGenerator.class) final Key key,
            final Instant timestamp, @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(CipherBytesGenerator.class) final byte[] cipherText) {
        final byte[] firstSignature = key.sign((byte) 0x80, timestamp, initializationVector, cipherText);
        final byte[] secondSignature = key.sign((byte) 0x80, timestamp, initializationVector, cipherText);

        assertEquals(firstSignature.length, 256 / 8);
        assertEquals(secondSignature.length, 256 / 8);
        assertTrue(Arrays.equals(firstSignature, secondSignature));
    }

    @Property
    public final void signaturesForSameParametersAndDifferentKeysAreDifferent(@From(KeyGenerator.class) final Key k0,
            @From(KeyGenerator.class) final Key k1, final Instant timestamp,
            @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(CipherBytesGenerator.class) final byte[] cipherText) {
        final byte[] firstSignature = k0.sign((byte) 0x80, timestamp, initializationVector, cipherText);
        final byte[] secondSignature = k1.sign((byte) 0x80, timestamp, initializationVector, cipherText);
        assertFalse(Arrays.equals(firstSignature, secondSignature));
        assertEquals(firstSignature.length, 256 / 8);
        assertEquals(secondSignature.length, 256 / 8);
    }

    @Property
    public final void signaturesForDifferentTimesAreDifferent(@From(KeyGenerator.class) final Key key,
            final Instant timestamp, @InRange(minLong = -4, maxLong = 4) final long offsetMillis,
            @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(CipherBytesGenerator.class) final byte[] cipherText) {
        assumeThat(offsetMillis, oneOf(greaterThan(0), lessThan(0)));

        final byte[] firstSignature = key.sign((byte) 0x80, timestamp, initializationVector, cipherText);
        final byte[] secondSignature = key.sign((byte) 0x80, timestamp.plusMillis(offsetMillis), initializationVector,
                cipherText);

        assertFalse(Arrays.equals(firstSignature, secondSignature));
        assertEquals(firstSignature.length, 256 / 8);
        assertEquals(secondSignature.length, 256 / 8);
    }

    @Property
    public final void signaturesForDifferentIVsAreDifferent(@From(KeyGenerator.class) final Key key,
            final Instant timestamp, @From(IvGenerator.class) final IvParameterSpec iv0,
            @From(IvGenerator.class) final IvParameterSpec iv1,
            @From(CipherBytesGenerator.class) final byte[] cipherText) {
        final byte[] firstSignature = key.sign((byte) 0x80, timestamp, iv0, cipherText);
        final byte[] secondSignature = key.sign((byte) 0x80, timestamp, iv1, cipherText);
        assertFalse(Arrays.equals(firstSignature, secondSignature));
        assertEquals(firstSignature.length, 256 / 8);
        assertEquals(secondSignature.length, 256 / 8);
    }

    @Property
    public final void signaturesForDifferentPayloadsAreDifferent(@From(KeyGenerator.class) final Key key,
            final Instant timestamp, @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(CipherBytesGenerator.class) final byte[] payload0,
            @From(CipherBytesGenerator.class) final byte[] payload1) {
        final byte[] firstSignature = key.sign((byte) 0x80, timestamp, initializationVector, payload0);
        final byte[] secondSignature = key.sign((byte) 0x80, timestamp, initializationVector, payload1);
        assertFalse(Arrays.equals(firstSignature, secondSignature));
        assertEquals(firstSignature.length, 256 / 8);
        assertEquals(secondSignature.length, 256 / 8);
    }

    @Property
    public final void encryptingWithSameParametersYieldsSameResults(@From(KeyGenerator.class) final Key key,
            @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(PlainBytesGenerator.class) final byte[] payload) {
        final byte[] firstCipher = key.encrypt(payload, initializationVector);
        final byte[] secondCipher = key.encrypt(payload, initializationVector);
        
        assertTrue(Arrays.equals(firstCipher, secondCipher));
        assertEquals((payload.length / 16 + 1) * 16, firstCipher.length);
        assertEquals((payload.length / 16 + 1) * 16, secondCipher.length);
    }

    @Property
    public final void encryptionAndDecryptionAreInverses(@From(KeyGenerator.class) final Key key,
            @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(PlainBytesGenerator.class) final byte[] payload) {
        final byte[] cipherText = key.encrypt(payload, initializationVector);
        final byte[] decrypted = key.decrypt(cipherText, initializationVector);

        assertFalse(Arrays.equals(cipherText, payload));
        assertEquals((payload.length / 16 + 1) * 16, cipherText.length);
        assertTrue(Arrays.equals(payload, decrypted));
    }

    @Property
    public final void encryptionWithDifferentKeysYieldsDifferentResults(@From(KeyGenerator.class) final Key k0,
            @From(KeyGenerator.class) final Key k1, @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(PlainBytesGenerator.class) final byte[] payload) {
        final byte[] firstCipher = k0.encrypt(payload, initializationVector);
        final byte[] secondCipher = k1.encrypt(payload, initializationVector);

        assertFalse(Arrays.equals(firstCipher, secondCipher));
        assertEquals((payload.length / 16 + 1) * 16, firstCipher.length);
        assertEquals((payload.length / 16 + 1) * 16, secondCipher.length);
        assertEquals(firstCipher.length, secondCipher.length);
    }

    @Property
    public final void encryptingDifferentPayloadsYieldsDifferentCiphers(@From(KeyGenerator.class) final Key key,
            @From(IvGenerator.class) final IvParameterSpec initializationVector,
            @From(PlainBytesGenerator.class) final byte[] p0, @From(PlainBytesGenerator.class) final byte[] p1) {
        final byte[] firstCipher = key.encrypt(p0, initializationVector);
        final byte[] secondCipher = key.encrypt(p1, initializationVector);

        assertFalse(Arrays.equals(firstCipher, secondCipher));
        assertEquals((p0.length / 16 + 1) * 16, firstCipher.length);
        assertEquals((p1.length / 16 + 1) * 16, secondCipher.length);
    }

    @Property
    public final void encryptingWithDifferentIVsYieldsDifferentCiphers(@From(KeyGenerator.class) final Key key,
            @From(IvGenerator.class) final IvParameterSpec iv0,
            @From(IvGenerator.class) final IvParameterSpec iv1,
            @From(PlainBytesGenerator.class) final byte[] payload) {
        final byte[] firstCipher = key.encrypt(payload, iv0);
        final byte[] secondCipher = key.encrypt(payload, iv1);

        assertFalse(Arrays.equals(firstCipher, secondCipher));
        assertEquals((payload.length / 16 + 1) * 16, firstCipher.length);
        assertEquals((payload.length / 16 + 1) * 16, secondCipher.length);
        assertEquals(firstCipher.length, secondCipher.length);
    }

    @Property
    public final void serialiseAndDeserialiseAreInverses(@From(KeyGenerator.class) final Key key) {
        final String serialised = key.serialise();
        final Key deserialised = new Key(serialised);
        assertEquals(key, deserialised);
    }

}