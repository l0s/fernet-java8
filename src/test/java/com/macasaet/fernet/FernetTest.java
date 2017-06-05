package com.macasaet.fernet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

import org.junit.Test;

public class FernetTest {

	private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

	/*
	 * Verify validation errors
	 * https://github.com/fernet/spec/blob/master/invalid.json
	 */

	@Test
	public final void incorrectMac() {
		// given
		final Token token = Token.fromString("gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
		final Instant now = Instant.from(formatter.parse("1985-10-26T01:20:01-07:00"));
		final Instant earliestValid = now.minusSeconds(60);
		final Instant latestValid = now.plusSeconds(60);

		// when
		final boolean result = token.isValid(key, earliestValid.getEpochSecond(), latestValid.getEpochSecond());

		// then
		assertFalse(token.isValidSignature(key));
		assertFalse(result);
	}

	@Test
	public final void tooShort() {
		// given
		final String invalidToken = "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==";

		try {
			// when
			Token.fromString(invalidToken);
			fail("Expected an exception");
		} catch (final IllegalArgumentException iae) {
			// then
		}
	}

	@Test
	public final void invalidBase64() {
		// given
		final String invalidToken = "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==";

		try {
			// when
			Token.fromString(invalidToken);
			fail("Expected an exception");
		} catch (final IllegalArgumentException iae) {
			// then
		}
	}

	@Test
	public final void payloadSizeNotMultipleOfBlockSize() {
		// given
		final String invalidToken = "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm";

		try {
			// when
			Token.fromString(invalidToken);
			fail("Expected an exception");
		} catch (final IllegalArgumentException iae) {
			// then
		}
	}

	@Test
	public final void payloadPaddingError() {
		// given
		final Token token = Token.fromString("gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
		final Instant now = Instant.from(formatter.parse("1985-10-26T01:20:01-07:00"));
		final Instant earliestValid = now.minusSeconds(60);
		final Instant latestValid = now.plusSeconds(60);

		// when
		final boolean result = token.isValid(key, earliestValid.getEpochSecond(), latestValid.getEpochSecond());

		// then
		assertFalse(result);
	}

	@Test
	public final void farFutureTimestamp() {
		// given
		final Token token = Token.fromString("gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
		
		final Instant now = Instant.from(formatter.parse("1985-10-26T01:20:01-07:00"));
		final Instant earliestValid = now.minusSeconds(60);
		final Instant latestValid = now.plusSeconds(60);

		// when
		final boolean result = token.isValid(key, earliestValid.getEpochSecond(), latestValid.getEpochSecond());

		// then
		assertFalse(
				"token timestamp: " + Instant.ofEpochSecond(token.getTimestamp()) + " / latest valid timestamp: " + latestValid,
				token.isNotTooFarInTheFuture(latestValid.getEpochSecond()));
		assertFalse(result);
	}

	@Test
	public final void expiredTtl() {
		// given
		final Token token = Token.fromString("gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
		final Instant now = Instant.from(formatter.parse("1985-10-26T01:21:31-07:00"));
		final Instant earliestValid = now.minusSeconds(60);
		final Instant latestValid = now.plusSeconds(60);

		// when
		final boolean result = token.isValid(key, earliestValid.getEpochSecond(), latestValid.getEpochSecond());

		// then
		assertFalse("token timestamp: " + Instant.ofEpochSecond(token.getTimestamp()) + " / earliest valid timestamp: "
				+ earliestValid, token.isNotExpired(earliestValid.getEpochSecond()));
		assertFalse(result);
	}

	/**
	 * Verify the scenario that the token has an incorrect initialization vector, which should cause a padding error
	 */
	@Test
	public final void incorrectInitializationVector() {
		// given
		final Token token = Token.fromString("gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
		final Instant now = Instant.from(formatter.parse("1985-10-26T01:20:01-07:00"));
		final Instant earliestValid = now.minusSeconds(60);
		final Instant latestValid = now.plusSeconds(60);

		// when
		final boolean result = token.isValid(key, earliestValid.getEpochSecond(), latestValid.getEpochSecond());

		// then
		assertFalse("token should be invalid", result);
	}

	/**
	 * Verify ability to generate well-formed token.
	 *
	 * https://github.com/fernet/spec/blob/master/generate.json
	 */
	@Test
	public final void generate() {
		// given
		final Token token = Token.fromString(
				"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

		// when
		final String result = token.decrypt(key);

		// then
		assertEquals("hello", result);
	}

	/**
	 * Verify ability to verify a valid token.
	 *
	 * https://github.com/fernet/spec/blob/master/verify.json
	 */
	@Test
	public final void verify() {
		// given
		final Token token = Token.fromString("gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==");
		final Key key = Key.fromString("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
		final Instant now = Instant.from(formatter.parse("1985-10-26T01:20:01-07:00"));
		final Instant earliestValid = now.minusSeconds(60);
		final Instant latestValid = now.plusSeconds(60);

		// when
		final boolean valid = token.isValid(key, earliestValid.getEpochSecond(), latestValid.getEpochSecond());
		final String payload = token.decrypt(key);

		// then
		assertTrue(token.isValidVersion());
		assertTrue(
				"token was generated on " + Instant.ofEpochSecond(token.getTimestamp()) + " but must be after " + earliestValid,
				token.isNotExpired(earliestValid.getEpochSecond()));
		assertTrue(token.isNotTooFarInTheFuture(latestValid.getEpochSecond()));
		assertTrue(token.isValidSignature(key));
		assertTrue(valid);
		assertEquals("hello", payload);
	}

}