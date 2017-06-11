package com.macasaet.fernet.example.jaxrs;

import java.security.SecureRandom;
import java.util.Random;

import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

@Path("session")
public class AuthenticationResource {

	@Inject
	Random random = new SecureRandom();
	private final Key key = Key.fromString("oTWTxEsH8OZ2jNR64dibSaBHyj_CX2RGP-eBRxjlkoc=");

	@Inject
	UserRepository repository;

	@POST
	@Produces("text/plain")
	public String createSession(final LoginRequest request) {
		final User user = repository.findUser(request.getUsername());
		if (user.isPasswordCorrect(request.getSingleRoundPasswordHash())) {
			// password is correct, so generate a Fernet token
			// payload is the username, but it could easily be JSON or XML
			final Token token = Token.generate(random, key, request.getUsername());
			System.out.println("-- generated token: " + token);
			return token.serialise();
		}
		throw new NotAuthorizedException(Response.status(Status.UNAUTHORIZED).entity("bad password").build());
	}

}
