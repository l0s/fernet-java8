package com.macasaet.fernet.example.jaxrs;

import java.util.function.Function;
import java.util.function.Predicate;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

@Path("secrets")
public class ProtectedResource {

	private final Key key = Key.fromString("oTWTxEsH8OZ2jNR64dibSaBHyj_CX2RGP-eBRxjlkoc=");

	@Inject
	UserRepository repository;

	private final Validator<User> validator = new Validator<User>() {
		public Function<String, User> getTransformer() {
			return repository::findUser;
		}

		public Predicate<User> getObjectValidator() {
			return User::isTrustworthy;
		}
	};

	@GET
	public String getSecret(@HeaderParam("X-Auth-Token") final String authHeader) {
		final Token token = Token.fromString(authHeader);
		token.validateAndDecrypt(key, validator);
		return "42";
	}

}