package com.macasaet.fernet.example.jaxrs;

import java.util.function.Function;
import java.util.function.Predicate;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.StringObjectValidator;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

/**
 * This is an example of a resource that is protected by Fernet tokens. In order
 * to access the resource, the client must pass a valid Fernet token that was
 * generated using the same secret key.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Path("secrets")
public class ProtectedResource {

	/**
	 * The secret key that is shared among server-side components. The protected
	 * resource does not need to run on the same infrastructure as the software
	 * that generated the token as long as it has access to the same secret key.
	 */
	final Key key = new Key("oTWTxEsH8OZ2jNR64dibSaBHyj_CX2RGP-eBRxjlkoc=");

	@Inject
	UserRepository repository;

	/**
	 * This is an example of a domain-specific token validator. It delegates to
	 * an external data store to convert the payload into an object. In
	 * addition, it applies domain-specific business rules to evaluate the
	 * deserialised payload.
	 */
    final Validator<User> validator = new StringObjectValidator<User>() {
        public Function<String, User> getStringTransformer() {
            return repository::findUser;
        }

        public Predicate<User> getObjectValidator() {
            return User::isTrustworthy;
        }
    };

    /**
     * This is a secured endpoint. The Fernet token is passed in via the X-Auth-Token header parameter.
     *
     * @param authHeader
     *            a Fernet token
     * @return the secret information
     */
    @GET
    public String getSecret(@HeaderParam("X-Auth-Token") final String authHeader) {
        // first, validate the token
        // if the token is valid, proceed to return the requested data
        final Token token = Token.fromString(authHeader);
        final User user = token.validateAndDecrypt(key, validator);
        // if the token is invalid, an exception will be thrown and the next line will not be executed
        // additional authorisation rules can be evaluated here such as ensuring the user specified by the token has
        // access to the data requested
        return user.getSecret();
    }

}