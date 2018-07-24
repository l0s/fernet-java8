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

import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;

import com.macasaet.fernet.jaxrs.exception.IllegalTokenExceptionMapper;

/**
 * {@link Feature} that enables Fernet token injection into Resource method parameters.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 * @see com.macasaet.fernet.jaxrs.FernetToken
 * @see com.macasaet.fernet.Token
 */
public class FernetTokenFeature implements Feature {

    public boolean configure(final FeatureContext context) {
        context.register(new FernetTokenBinder());
        context.register(IllegalTokenExceptionMapper.class);
        return true;
    }

}