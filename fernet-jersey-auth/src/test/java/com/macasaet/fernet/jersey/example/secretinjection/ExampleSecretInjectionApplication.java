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
package com.macasaet.fernet.jersey.example.secretinjection;

import java.util.Collection;
import java.util.function.Supplier;
import java.util.logging.Logger;

import javax.inject.Singleton;
import javax.ws.rs.core.GenericType;

import com.macasaet.fernet.jersey.example.common.*;
import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.internal.inject.Binder;
import org.glassfish.jersey.logging.LoggingFeature;
import org.glassfish.jersey.logging.LoggingFeature.Verbosity;
import org.glassfish.jersey.server.ResourceConfig;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jersey.FernetSecretFeature;

/**
 * <p>This is an example Jersey application configuration that enables injection of a Fernet token payload. Your
 * application <strong>must</strong> provide a <code>Validator&lt;T&gt;</code> implementation where <code>T</code> is
 * the payload type. Your application <strong>must</strong> also provide a
 * <code>Supplier&lt;Collection&lt;Key&gt;&gt;</code> implementation that provides the decryption and signing keys for
 * potential Fernet tokens that may be submitted.</p>
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @see FernetSecretFeature
 * @see com.macasaet.fernet.jaxrs.FernetSecret
 * @param <T> the payload type. This is needed for injection to work.
 * @author Carlos Macasaet
 */
public class ExampleSecretInjectionApplication<T> extends ResourceConfig {

    private final Binder fernetParameterBinder = new AbstractBinder() {
        protected void configure() {
            bind(UserRepository.class).to(UserRepository.class).in(Singleton.class);
            bind(SessionRepository.class).to(SessionRepository.class).in(Singleton.class);
            bind(PasswordService.class).to(PasswordService.class).in(Singleton.class);
            bind(CustomTokenValidator.class).to(new GenericType<Validator<T>>(){}).in(Singleton.class);
            bind(CustomTokenValidator.class).to(new GenericType<Validator<Session>>(){}).in(Singleton.class);
            bind(KeySupplier.class).to(new GenericType<Supplier<Collection<Key>>>(){}).in(Singleton.class);
        }
    };
    public ExampleSecretInjectionApplication() {
        register(new LoggingFeature(Logger.getLogger("SecretInjectionApplication"), Verbosity.PAYLOAD_ANY));
        register(FernetSecretFeature.class);
        register(fernetParameterBinder);
        register(AuthenticationResource.class);
        register(ProtectedResource.class);
    }
}