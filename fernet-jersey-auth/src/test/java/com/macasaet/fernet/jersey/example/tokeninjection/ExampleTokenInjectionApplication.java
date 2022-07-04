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
package com.macasaet.fernet.jersey.example.tokeninjection;

import java.util.Collection;
import java.util.function.Supplier;

import javax.inject.Singleton;
import javax.ws.rs.core.GenericType;

import com.macasaet.fernet.jersey.example.common.*;
import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.internal.inject.Binder;
import org.glassfish.jersey.server.ResourceConfig;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jersey.FernetTokenFeature;

/**
 * <p>This is an example Jersey application configuration that enables injection of a Fernet token.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @see com.macasaet.fernet.jersey.FernetTokenFeature
 * @see com.macasaet.fernet.jaxrs.FernetToken
 * @author Carlos Macasaet
 */
public class ExampleTokenInjectionApplication extends ResourceConfig {

    private final Binder fernetConfigurationBinder = new AbstractBinder() {
        protected void configure() {
            bind(UserRepository.class).to(UserRepository.class).in(Singleton.class);
            bind(PasswordService.class).to(PasswordService.class).in(Singleton.class);
            bind(SessionRepository.class).to(SessionRepository.class).in(Singleton.class);
            bind(CustomTokenValidator.class).to(new GenericType<Validator<Session>>(){}).in(Singleton.class);
            bind(KeySupplier.class).to(new GenericType<Supplier<Collection<Key>>>(){}).in(Singleton.class);
        }
    };

    public ExampleTokenInjectionApplication() {
        register(fernetConfigurationBinder);
        register(FernetTokenFeature.class);
        register(AuthenticationResource.class);
        register(ProtectedResource.class);
    }

}