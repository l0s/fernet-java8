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
package com.macasaet.fernet.jaxrs.exception;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import com.macasaet.fernet.IllegalTokenException;

/**
 * An {@link ExceptionMapper} that translates Fernet token creation exceptions into HTTP semantics.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Provider
public class IllegalTokenExceptionMapper implements ExceptionMapper<IllegalTokenException> {

    public Response toResponse(final IllegalTokenException exception) {
        return new NotAuthorizedException("Bearer error=\"invalid_token\", error_description=\"mal-formed token\"").getResponse();
    }

}