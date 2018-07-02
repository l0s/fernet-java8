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
package com.macasaet.fernet.jersey.payloadinjection;

import java.util.Collection;
import java.util.function.Supplier;

import javax.ws.rs.core.GenericType;

import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.internal.inject.Binder;
import org.glassfish.jersey.server.ResourceConfig;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Validator;
import com.macasaet.fernet.jersey.FernetSecretBinder;


public class ExampleSecretInjectionApplication<T> extends ResourceConfig {

    private final Binder fernetParameterBinder = new AbstractBinder() {
        {
            System.out.println("-- instantiating parameter binder");
        }
        // TODO perhaps make an abstract class? implementors supply key supplier and validator
        protected void configure() {
            System.out.println("-- configuring bindings");
            bind(CustomTokenValidator.class).to(new GenericType<Validator<T>>(){});
            bind(KeySupplier.class).to(new GenericType<Supplier<Collection<Key>>>(){});
        }
    };
    public ExampleSecretInjectionApplication() {
        System.out.println("-- ExampleSecretInjectionApplication()");
        register(new FernetSecretBinder());
        register(fernetParameterBinder);
        register(ExampleSecretInjectionResource.class);
    }
}