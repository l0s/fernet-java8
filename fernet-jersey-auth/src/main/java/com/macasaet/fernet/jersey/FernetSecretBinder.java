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

import javax.inject.Singleton;

import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.server.spi.internal.ValueParamProvider;

/**
 * {@link org.glassfish.jersey.internal.inject.Binder Binder} that configures Fernet payload injection.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 * @see com.macasaet.fernet.jaxrs.FernetSecret
 * @see FernetSecretFeature
 */
@SuppressWarnings("PMD.LawOfDemeter")
class FernetSecretBinder extends AbstractBinder {

    protected void configure() {
        bind(FernetSecretValueParamProvider.class)
            .to(ValueParamProvider.class)
            .in(Singleton.class);
    }

}