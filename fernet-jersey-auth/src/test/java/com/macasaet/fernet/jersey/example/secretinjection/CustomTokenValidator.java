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

import java.util.function.Function;
import java.util.function.Predicate;

import javax.inject.Inject;
import javax.inject.Singleton;

import com.macasaet.fernet.StringObjectValidator;
import com.macasaet.fernet.jersey.example.common.User;
import com.macasaet.fernet.jersey.example.common.UserRepository;

/**
 * This {@link com.macasaet.fernet.Validator Validator} assumes that the Fernet Token payload is a username. It obtains
 * a User POJO from a datastore and validates that the User is trustworthy.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
@Singleton
public class CustomTokenValidator implements StringObjectValidator<User> {

    @Inject
    private UserRepository repository;

    public Function<String, User> getStringTransformer() {
        return repository::findUser;
    }

    public Predicate<User> getObjectValidator() {
        return User::isTrustworthy;
    }

}