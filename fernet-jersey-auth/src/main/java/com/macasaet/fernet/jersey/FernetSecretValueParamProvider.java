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

import java.util.Collection;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.NotAuthorizedException;

import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueParamProvider;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jaxrs.FernetSecret;

/**
 * A {@link ValueParamProvider} to configure a Jersey JAX-RS application to inject
 * Fernet token payloads into Resource Method Parameters. Your application will need to provide a custom
 * {@link Validator} implementation that extracts the payload from the token and a {@link Supplier} that provides valid
 * Fernet keys.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 * @param <T>
 *            The type of payload that is stored in the Fernet Tokens and will be injected into the JAX-RS Resource.
 * @see FernetSecretValueParamProvider#FernetPayloadValueParamProvider(Validator, Supplier)
 */
@Singleton
class FernetSecretValueParamProvider<T> implements ValueParamProvider {

    private final TokenHeaderUtility headerUtility;
    private final Validator<T> validator;
    private final Supplier<Collection<Key>> keySupplier;

    /**
     * @param validator custom token verifier and payload extractor
     * @param keySupplier a method to provide Fernet keys
     */
    @Inject
    public FernetSecretValueParamProvider(final Validator<T> validator,
            final Supplier<Collection<Key>> keySupplier) {
        this(validator, keySupplier, new TokenHeaderUtility());
    }

    /**
     * @param validator custom token verifier and payload extractor
     * @param keySupplier a method to provide Fernet keys
     * @param headerUtility a helper for parsing tokens from auth headers
     */
    protected FernetSecretValueParamProvider(final Validator<T> validator, final Supplier<Collection<Key>> keySupplier,
            final TokenHeaderUtility headerUtility) {
        if (validator == null) {
            throw new IllegalArgumentException("validator cannot be null");
        }
        if (keySupplier == null) {
            throw new IllegalArgumentException("keySupplier cannot be null");
        }
        if (headerUtility == null) {
            throw new IllegalArgumentException("headerUtility cannot be null");
        }
        this.validator = validator;
        this.keySupplier = keySupplier;
        this.headerUtility = headerUtility;
    }

    public Function<ContainerRequest, T> getValueProvider(final Parameter parameter) {
        return request -> {
            if (parameter.isAnnotationPresent(FernetSecret.class)) {
                final Collection<? extends Key> keys = getKeySupplier().get();
                final Token xAuthorizationToken = getHeaderUtility().getXAuthorizationToken(request);
                if (xAuthorizationToken != null) {
                    return getValidator().validateAndDecrypt(keys, xAuthorizationToken);
                }
                final Token authorizationToken = getHeaderUtility().getAuthorizationToken(request);
                if (authorizationToken != null) {
                    return getValidator().validateAndDecrypt(keys, authorizationToken);
                }
                throw new NotAuthorizedException("Bearer error=\"invalid_token\", error_description=\"no token found in Authorization or X-Authorization header\"");
            }
            throw new IllegalStateException("misconfigured annotation");
        };
    }

    public PriorityType getPriority() {
        return NORMAL;
    }

    protected Validator<T> getValidator() {
        return validator;
    }

    protected Supplier<? extends Collection<? extends Key>> getKeySupplier() {
        return keySupplier;
    }

    protected TokenHeaderUtility getHeaderUtility() {
        return headerUtility;
    }

}