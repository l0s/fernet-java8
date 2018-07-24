/**
   Copyright 2018 Carlos Macasaet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package com.macasaet.fernet.jersey.example.secretinjection;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

import com.macasaet.fernet.jaxrs.FernetSecret;
import com.macasaet.fernet.jersey.example.common.User;

/**
 * This is an example of a resource that is protected by Fernet tokens. In order
 * to access the resource, the client must pass a valid Fernet token that was
 * generated using the same secret key.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Path("secrets")
public class ProtectedResource {

    /**
     * This is a secured endpoint. The Fernet token is passed in via the X-Auth-Token header parameter.
     *
     * @param authHeader
     *            a Fernet token
     * @return the secret information
     */
    @GET
    public String getSecret(@FernetSecret final User user) {
        // if the token is invalid, an exception will be thrown and the next line will not be executed
        // additional authorisation rules can be evaluated here such as ensuring the user specified by the token has
        // access to the data requested
        return user.getSecret();
    }

}