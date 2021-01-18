# Fernet Java - Jersey JAX-RS Integration

[![Javadocs](https://javadoc.io/badge/com.macasaet.fernet/fernet-jersey-auth.svg)](https://javadoc.io/doc/com.macasaet.fernet/fernet-jersey-auth)
[![Known Vulnerabilities](https://snyk.io/test/github/l0s/fernet-java8/badge.svg?targetFile=fernet-jersey-auth%2Fpom.xml)](https://snyk.io/test/github/l0s/fernet-java8?targetFile=fernet-jersey-auth%2Fpom.xml)

This library provides annotations and Jersey integration so that REST endpoints can be secured by Fernet authenticated, encrypted tokens.

## Client usage

Clients should pass Fernet tokens in either the `X-Authorization` header or using the `Authorization` header with the scheme "Bearer" (RFC 6750). Examples:

    curl --header 'X-Authorization: gAAAAABbPXSD3PW756Xpct7qRrvk-aVayPc1MMJPyNzO-uisHWWZfQWVoLZ0GQVSSGqLS5yTdEe0BAHTw2ZpAsnDpFB80UC-MA==' \
        https://api.example.com/resource/endpoint?parameter=value

    curl --header 'Authorization: Bearer gAAAAABbPXSD3PW756Xpct7qRrvk-aVayPc1MMJPyNzO-uisHWWZfQWVoLZ0GQVSSGqLS5yTdEe0BAHTw2ZpAsnDpFB80UC-MA==' \
        https://api.example.com/resource/endpoint?parameter=value

## Server-side implementation

The JAX-RS application may receive the Fernet tokens either as
[Token](https://javadoc.io/page/com.macasaet.fernet/fernet-java8/latest/com/macasaet/fernet/Token.html)
objects or as the specific payload type that is stored inside the token
(e.g. a data transfer object, a type-safe identifier, or a String). Note:
*do not use this library to implement stateless sessions*. Ensure that
sessions can be revoked prior to Fernet token expiration.

### Token Injection

With Token injection, it is up to the application to validate the token, extract its payload, and respond with the appropriate HTTP semantics if the token is not valid. For a full, end-to-end example, see [TokenInjectionIT](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/tokeninjection/TokenInjectionIT.java).

#### Resource

Add a Token parameter to the argument list for an endpoint method within a resource class and annotate it with the `@FernetToken` annotation. e.g.:

    import javax.ws.rs.*;
    import com.macasaet.fernet.jaxrs.FernetToken;
    import com.macasaet.fernet.Token;
    
    @Path("/users")
    public class UserResource {
        @GET
        @Produces("application/json")
        public User getUser(@FernetToken final Token token) {
            // The system will convert the header into a Token
            // It is up to the Resource developer to validate the token and extract its contents.
        }
    } 

For a full example, see [ProtectedResource](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/tokeninjection/ProtectedResource.java).

#### Application Configuration

Inside the application configuration (`ResourceConfig`), register an instance of `FernetTokenBinder`. e.g.:

    import org.glassfish.jersey.server.ResourceConfig;
    import com.macasaet.fernet.jersey.FernetTokenBinder;
    
    public class Application extends ResourceConfig {
        public Application() {
            register(new FernetTokenBinder());
        }
    }

For a full example, see [ExampleTokenInjectionApplication](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/tokeninjection/ExampleTokenInjectionApplication.java).

### Secret / Payload Injection

With Secret injection, fernet-jersey-auth will automatically validate the token, extract the token, then provide it to the resource endpoint. If the token is invalid, the library will respond with the appropriate HTTP status code. For a full example, see [SecretInjectionIT](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/secretinjection/SecretInjectionIT.java).

#### Resource

Add a POJO parameter to the argument list for an endpoint method within a resource class and annotate it with the `@FernetSecret` annotation. e.g.:

    import javax.ws.rs.*;
    @Path("/users")
    public class UserResource {
        @POST
        @Produces("application/json")
        public User getUser(@FernetSecret final Session session) {
            // The system will validate the token, extract the payload, and provide it to the endpoint.
            // The `Validator` you provide will be responsible for ensuring
            // the POJO is valid according to your business and security
            // needs.
        }
    }

For a full example, see [ProtectedResource](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/secretinjection/ProtectedResource.java).

#### Application Configuration

Inside the application configuration (`ResourceConfig`), configure dependency injection to bind a custom `Validator<T>` implementation and a custom `Supplier<Collection<Key>>` implementation. The `T` parameter should be the type of payload inside the token and the `Supplier` should provide the current valid decryption / verification keys. Both of these may be singletons and, if necessary, may make remote calls. Finally, register `FernetSecretFeature`. Example:

    import java.util.function.Supplier;
    import java.util.Collection;
    import javax.ws.rs.core.GenericType;
    import org.glassfish.jersey.server.ResourceConfig;
    import org.glassfish.jersey.internal.inject.*;
    import com.macasaet.fernet.*;
    import com.macasaet.fernet.jersey.FernetSecretFeature;
    
    // The <T> parameter is required by Jersey dependency injection in order to discover the Validator
    public class Application<T> extends ResourceConfig {
        private final Binder fernetParameterBinder = new AbstractBinder() {
            protected void configure() {
                bind(MyValidator.class).to(new GenericType<Validator<T>>(){});
                bind(MyKeySupplier.class).to(new GenericType<Supplier<Collection<Key>>>(){});
            }
        };
        public Application() {
            register(fernetParameterBinder);
            register(FernetSecretFeature.class);
        }
    }

For a full example, see [ExampleSecretInjectionApplication](https://github.com/l0s/fernet-java8/blob/master/fernet-jersey-auth/src/test/java/com/macasaet/fernet/jersey/example/secretinjection/ExampleSecretInjectionApplication.java).

## Compatibility

This was developed and tested against Jersey 2.27. It may work with versions as early as 2.26. However, it will not work with any versions earlier than that as 2.26 introduced [backward-incompatible changes](https://jersey.github.io/release-notes/2.26.html) to the dependency injection mechanism.

### Other JAX-RS / JSR 311 implementations

Although this library is specific to the Jersey implementation, if you are using a different JAX-RS / JSR 311 implementation, you may still use the annotations in [com.macasaet.fernet.jaxrs](https://github.com/l0s/fernet-java8/tree/master/fernet-jersey-auth/src/main/java/com/macasaet/fernet/jaxrs) and the exception mappers in [com.macasaet.fernet.jaxrs.exception](https://github.com/l0s/fernet-java8/tree/master/fernet-jersey-auth/src/main/java/com/macasaet/fernet/jaxrs/exception). However, you will need to write the header parsing and object injection functionality yourself.

## License

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
