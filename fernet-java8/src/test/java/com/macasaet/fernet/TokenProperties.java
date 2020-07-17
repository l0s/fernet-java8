package com.macasaet.fernet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import org.junit.runner.RunWith;

import com.macasaet.fernet.property.KeyGenerator;
import com.pholser.junit.quickcheck.From;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;

@RunWith(JUnitQuickcheck.class)
public class TokenProperties {

    @Property
    public final void tokenWithSameKey(@From(KeyGenerator.class) final Key key, final String plainText)
            throws UnsupportedEncodingException {
        // given
        // when
        final Token token = Token.generate(key, plainText);

        // then
        assertTrue(token.isValidSignature(key));
        assertEquals((byte) 0x80, token.getVersion());
        assertFalse(Instant.now().isBefore(token.getTimestamp()));
        assertEquals(128 / 8, token.getInitializationVector().getIV().length);
        assertEquals(256 / 8, token.getHmac().length);
        final int expectedCipherLength = (plainText.getBytes("UTF-8").length / 16 + 1) * 16;
        assertEquals(expectedCipherLength, token.getCipherText().length);
    }

    @Property
    public final void tokensWithDifferentKeys(@From(KeyGenerator.class) final Key validKey,
            @From(KeyGenerator.class) final Key invalidKey, final String plainText) {
        final Token token = Token.generate(validKey, plainText);

        assertFalse(token.isValidSignature(invalidKey));
    }

    @Property
    public final void tokensWithDifferentPayloads(@From(KeyGenerator.class) final Key key, final String p0,
            final String p1) {
        // given
        // when
        final Token firstToken = Token.generate(key, p0);
        final Token secondToken = Token.generate(key, p1);

        // then
        assertFalse(secondToken.getTimestamp().isBefore(firstToken.getTimestamp()));
        assertFalse(Arrays.equals(firstToken.getInitializationVector().getIV(),
                secondToken.getInitializationVector().getIV()));
        assertFalse(Arrays.equals(firstToken.getHmac(), secondToken.getHmac()));
        assertFalse(Arrays.equals(firstToken.getCipherText(), secondToken.getCipherText()));
        assertEquals(firstToken.getVersion(), secondToken.getVersion());
    }

    @Property
    public final void sameKeyAndPayloadYieldDistinctTokens(@From(KeyGenerator.class) final Key key,
            final String plainText) {
        // given
        // when
        final Token firstToken = Token.generate(key, plainText);
        final Token secondToken = Token.generate(key, plainText);

        // then
        assertFalse(secondToken.getTimestamp().isBefore(firstToken.getTimestamp()));
        assertFalse(Arrays.equals(firstToken.getInitializationVector().getIV(),
                secondToken.getInitializationVector().getIV()));
        assertFalse(Arrays.equals(firstToken.getHmac(), secondToken.getHmac()));
        assertFalse(Arrays.equals(firstToken.getCipherText(), secondToken.getCipherText()));
        assertEquals(firstToken.getVersion(), secondToken.getVersion());
    }

    @Property
    public final void serialiseGeneratesBase64(@From(KeyGenerator.class) final Key key, final String plainText) {
        // given
        final Token token = Token.generate(key, plainText);

        // when
        final String string = token.serialise();

        // then
        Base64.getUrlDecoder().decode(string);
    }

    @Property
    public final void serialiseDeserialiseAreInverses(@From(KeyGenerator.class) final Key key, final String plainText) {
        // given
        final Token token = Token.generate(key, plainText);

        // when
        final String string = token.serialise();
        final Token deserialised = Token.fromString(string);

        // then
        assertTrue(
                Arrays.equals(token.getInitializationVector().getIV(), deserialised.getInitializationVector().getIV()));
        assertEquals(token.getTimestamp().toEpochMilli(), deserialised.getTimestamp().toEpochMilli());
        assertEquals(token.getVersion(), deserialised.getVersion());
        assertTrue(Arrays.equals(token.getCipherText(), deserialised.getCipherText()));
        assertTrue(Arrays.equals(token.getHmac(), deserialised.getHmac()));
    }
}