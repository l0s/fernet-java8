/**
   Copyright 2018 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package com.macasaet.fernet.jersey;

import static org.glassfish.jersey.server.spi.internal.ValueParamProvider.Priority.NORMAL;

import java.util.function.Function;

import javax.inject.Singleton;
import javax.ws.rs.NotAuthorizedException;

import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueParamProvider;

import com.macasaet.fernet.Token;
import com.macasaet.fernet.jaxrs.FernetToken;

/**
 * {@link ValueParamProvider} that generates a Fernet {@link Token} from a REST request's auth header.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @see https://stackoverflow.com/a/50980611/914887
 * @author Carlos Macasaet
 */
@Singleton
class FernetTokenValueParamProvider implements ValueParamProvider {

    private final TokenHeaderUtility tokenHeaderUtility;

    public FernetTokenValueParamProvider() {
        this(new TokenHeaderUtility());
    }

    protected FernetTokenValueParamProvider(final TokenHeaderUtility tokenHeaderUtility) {
        if (tokenHeaderUtility == null) {
            throw new IllegalArgumentException("tokenHeaderUtility cannot be null");
        }
        this.tokenHeaderUtility = tokenHeaderUtility;
    }

    public Function<ContainerRequest, Token> getValueProvider(final Parameter parameter) {
        return request -> {
            if (parameter.getRawType().equals(Token.class) && parameter.isAnnotationPresent(FernetToken.class)) {
                final Token xAuthorizationToken = getTokenHeaderUtility().getXAuthorizationToken(request);
                if (xAuthorizationToken != null) {
                    return xAuthorizationToken;
                }
                final Token authorizationToken = getTokenHeaderUtility().getAuthorizationToken(request);
                if (authorizationToken != null) {
                    return authorizationToken;
                }
                throw new NotAuthorizedException("Bearer error=\"invalid_token\", error_description=\"no token found in Authorization or X-Authorization header\"");
            }
            throw new IllegalStateException("misconfigured annotation");
        };
    }

    public PriorityType getPriority() {
        return NORMAL;
    }

    protected TokenHeaderUtility getTokenHeaderUtility() {
        return tokenHeaderUtility;
    }

}