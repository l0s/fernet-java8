package com.macasaet.fernet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.Before;
import org.junit.Test;

public class TokenValidatorTest {

	private TokenValidator validator;

	@Before
	public void setUp() {
		validator = new TokenValidator();
	}

	@Test
	public void testValidateAndDecryptValidToken() {
		// given
		final Key key = mock(Key.class);
		final Token token = mock(Token.class);
		given(token.validateAndDecrypt(eq(key), anyLong(), anyLong())).willReturn("plaintext");

		// when
		final String result = validator.validateAndDecrypt(key, token);

		// then
		assertEquals("plaintext", result);
	}

	@Test
	public void testValidateAndDecryptInvalidToken() {
		// given
		final Key key = mock(Key.class);
		final Token token = mock(Token.class);
		given(token.validateAndDecrypt(eq(key), anyLong(), anyLong())).willThrow(new TokenValidationException("invalid token"));

		// when
		try {
			validator.validateAndDecrypt(key, token);
			fail("Expected an exception");
		} catch (final TokenValidationException tve) {
			// then
		}
	}

}