package com.macasaet.fernet.example.jaxrs;

import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;
import java.util.Random;

import javax.ws.rs.NotAuthorizedException;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * This test demonstrates how Fernet tokens can be used with JAX-RS (Jersey).
 *
 * @author Carlos Macasaet
 */
public class JaxRsTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Random random;
	private UserRepository userRepository;
	private AuthenticationResource authenticationResource;
	private ProtectedResource protectedResource;

	@Before
	public void setUp() {
		random = new SecureRandom();
		userRepository = new UserRepository();
		authenticationResource = new AuthenticationResource();
		authenticationResource.random = random;
		authenticationResource.repository = userRepository;
		protectedResource = new ProtectedResource();
		protectedResource.repository = userRepository;
	}

	@Test
	public final void verifySuccessfulBusinessRuleCheck() {
		// given
		final LoginRequest login = new LoginRequest("alice", "1QYCGznPQ1z8T1aX_CNXKheDMAnNSfq_xnSxWXPLeKU=");
		final String tokenString = authenticationResource.createSession(login);
		System.out.println("-- token: " + tokenString);

		// when
		final String result = protectedResource.getSecret(tokenString);

		// then
		assertEquals("42", result);
	}

	@Test
	public final void verifyFailedBusinessRuleCheck() {
		// given
		final LoginRequest login = new LoginRequest("mallory", "Lpei3NWxhPsyc5NrJp6zkbHj4P_bji6Z7GsY0JSAUb8=");
		final String tokenString = authenticationResource.createSession(login);

		// when
		thrown.expect(RuntimeException.class);
		protectedResource.getSecret(tokenString);

		// then (nothing)
	}

	@Test
	public final void verifyFailedLogin() {
		// given
		final LoginRequest login = new LoginRequest("bob", "NReIudfT_iovLMo-MCX8sClVr3UwbeEhAq7er6X_Kps=");

		// when
		thrown.expect(NotAuthorizedException.class);
		authenticationResource.createSession(login);

		// then (nothing)
	}

}