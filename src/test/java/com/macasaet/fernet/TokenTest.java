package com.macasaet.fernet;

import static com.macasaet.fernet.Constants.initializationVectorBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Random;

import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;

/**
 * Unit tests for the {@link Token} class.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class TokenTest {

	private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

	@Test
	public void testFromString() {
		// given
		final String string = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==";

		// when
		final Token result = Token.fromString(string);

		// then
		assertEquals((byte) 0x80, result.getVersion());
		assertEquals(Instant.from(formatter.parse("1985-10-26T01:20:00-07:00")),
				Instant.ofEpochSecond(result.getTimestamp()));
		assertArrayEquals(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
				result.getInitializationVector().getIV());
	}

	@Test
	public void testGenerate() {
		// given
		final Random deterministicRandom = new Random() {
			private static final long serialVersionUID = 3075400891983079965L;
			public void nextBytes(final byte[] bytes) {
				for( int i = bytes.length; --i >= 0; bytes[ i ] = 1 );
			}
		};
		final Key key = Key.generateKey(deterministicRandom);

		// when
		final Token result = Token.generate(deterministicRandom, key, "Hello, world!");

		// then
		final Instant now = Instant.now();
		assertTrue(result.isNotExpired(now.minusSeconds(120).getEpochSecond()));
		assertTrue(result.isNotTooFarInTheFuture(now.plusSeconds(120).getEpochSecond()));
		assertTrue(result.isValidVersion());
		assertTrue(result.isValidSignature(key));
		assertTrue(result.isValid(key, now.minusSeconds(120).getEpochSecond(), now.plusSeconds(120).getEpochSecond()));
	}
/*
	@Test
	public void testIsValid() {
		fail("Not yet implemented");
	}
*/
	@Test
	public void testDecryptKey() {
		// given
		final Random deterministicRandom = new Random() {
			private static final long serialVersionUID = 3075400891983079965L;
			public void nextBytes(byte[] bytes) {
				for( int i = initializationVectorBytes; --i >= 0; bytes[ i ] = 1 );
			}
		};
		final Key key = new Key(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
				new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
		final Token token = Token.generate(deterministicRandom, key, "Hello, world!");

		// when
		final String result = token.decrypt(key);

		// then
		assertEquals("Hello, world!", result);
	}

	@Test
	public void testSerialise() {
		// given
		final IvParameterSpec initializationVector = new IvParameterSpec(
				new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
		final Token invalidToken = new Token((byte) 0x80, 0l, initializationVector,
				new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
				new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
						26, 27, 28, 29, 30, 31, 32 });

		// when
		final String result = invalidToken.serialise();

		// then
		assertEquals(
				"gAAAAAAAAAAAAQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODxABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA==",
				result);
	}

}