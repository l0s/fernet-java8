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
package com.macasaet.fernet.jersey.example.common;

import static java.util.Collections.singleton;

import java.util.Collection;
import java.util.function.Supplier;

import javax.inject.Singleton;

import com.macasaet.fernet.Key;

@Singleton
public class KeySupplier implements Supplier<Collection<? extends Key>> {

    private static final Key key = new Key("oTWTxEsH8OZ2jNR64dibSaBHyj_CX2RGP-eBRxjlkoc=");

    public Collection<? extends Key> get() {
        // alternatively, get this from a datastore or secure key storage like AWS Secrets Manager, AWS KMS, or HashiCorp Vault
        return singleton(key);
    }

}