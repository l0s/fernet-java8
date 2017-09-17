package com.macasaet.fernet;

import static org.junit.Assert.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test class that validates the the scenarios in the <a href="https://github.com/fernet/spec">Fernet Spec</a>.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 * @see https://github.com/fernet/spec
 */
public class FernetTest {

	private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Instant now = Instant.from(formatter.parse("1985-10-26T01:20:01-07:00"));
	private Validator<String> validator;

    @Before
    public void setUp() {
        validator = new StringValidator() {
            public Clock getClock() {
                return Clock.fixed(now, ZoneOffset.UTC);
            }
        };
    }

    /*
     * Verify validation errors https://github.com/fernet/spec/blob/master/invalid.json
     */

    @Test
    public final void incorrectMac() {
        // given
        final Token token = Token.fromString(
                "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==");
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

        // when
        thrown.expect(TokenValidationException.class);
        token.validateAndDecrypt(key, validator);

        // then (nothing)
    }

    @Test
    public final void tooShort() {
        // given
        final String invalidToken = "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==";

        // when
        thrown.expect(IllegalArgumentException.class);
        Token.fromString(invalidToken);

        // then (nothing)
    }

    @Test
    public final void invalidBase64() {
        // given
        final String invalidToken = "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==";

        // when
        thrown.expect(IllegalArgumentException.class);
        Token.fromString(invalidToken);

        // then (nothing)
    }

    @Test
    public final void payloadSizeNotMultipleOfBlockSize() {
        // given
        final String invalidToken = "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm";

        // when
        thrown.expect(IllegalArgumentException.class);
        Token.fromString(invalidToken);

        // then (nothing)
    }

    @Test
    public final void payloadPaddingError() {
        // given
        final Token token = Token.fromString(
                "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==");
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

        // when
        thrown.expect(TokenValidationException.class);
        token.validateAndDecrypt(key, validator);

        // then (nothing)
    }

    @Test
    public final void farFutureTimestamp() {
        // given
        final Token token = Token.fromString(
                "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==");
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

        // when
        thrown.expect(TokenValidationException.class);
        token.validateAndDecrypt(key, validator);

        // then (nothing)
    }

    @Test
    public final void expiredTtl() {
        // given
        final Token token = Token.fromString(
                "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==");
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
        now = Instant.from(formatter.parse("1985-10-26T01:21:31-07:00"));

        // when
        thrown.expect(TokenValidationException.class);
        thrown.reportMissingExceptionWithMessage("Token should be expired: " + token);
        token.validateAndDecrypt(key, validator);

        // then (nothing)
    }

    /**
     * Verify the scenario that the token has an incorrect initialization vector, which should cause a padding error
     */
    @Test
    public final void incorrectInitializationVector() {
        // given
        final Token token = Token.fromString(
                "gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ==");
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

        // when
        thrown.expect(TokenValidationException.class);
        token.validateAndDecrypt(key, validator);

        // then
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
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

        // when
        final String result = token.validateAndDecrypt(key, validator);

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
        final Token token = Token.fromString(
                "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==");
        final Key key = new Key("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");

        // when
        final String result = token.validateAndDecrypt(key, validator);

        // then
        assertEquals("hello", result);
    }

}