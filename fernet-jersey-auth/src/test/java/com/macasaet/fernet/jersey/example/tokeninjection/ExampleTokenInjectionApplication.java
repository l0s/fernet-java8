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

import javax.ws.rs.core.GenericType;

import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.internal.inject.Binder;
import org.glassfish.jersey.logging.LoggingFeature;
import org.glassfish.jersey.server.ResourceConfig;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jersey.FernetTokenBinder;
import com.macasaet.fernet.jersey.example.common.AuthenticationResource;
import com.macasaet.fernet.jersey.example.common.User;
import com.macasaet.fernet.jersey.example.common.UserRepository;
import com.macasaet.fernet.jersey.example.secretinjection.CustomTokenValidator;
import com.macasaet.fernet.jersey.example.secretinjection.KeySupplier;


public class ExampleTokenInjectionApplication extends ResourceConfig {

    private final Binder fernetConfigurationBinder = new AbstractBinder() {
        protected void configure() {
            bind(UserRepository.class).to(UserRepository.class);
            bind(CustomTokenValidator.class).to(new GenericType<Validator<User>>(){});
            bind(KeySupplier.class).to(new GenericType<Supplier<Collection<Key>>>(){});
        }
    };

    public ExampleTokenInjectionApplication() {
        register(LoggingFeature.class);
        property(LoggingFeature.LOGGING_FEATURE_LOGGER_NAME_SERVER, "FINE");
        register(fernetConfigurationBinder);
        register(new FernetTokenBinder());
        register(AuthenticationResource.class);
        register(ProtectedResource.class);
    }

}