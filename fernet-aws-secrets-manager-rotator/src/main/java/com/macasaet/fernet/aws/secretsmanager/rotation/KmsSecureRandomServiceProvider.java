/**
   Copyright 2017 Carlos Macasaet

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
package com.macasaet.fernet.aws.secretsmanager.rotation;

import java.nio.ByteBuffer;
import java.security.SecureRandomSpi;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;

public class KmsSecureRandomServiceProvider extends SecureRandomSpi {

    private static final long serialVersionUID = 5664164482263548749L;
    private final AWSKMS kms;

    public KmsSecureRandomServiceProvider(final AWSKMS kms) {
        this.kms = kms;
    }

    protected void engineSetSeed(byte[] seed) {
    }

    protected void engineNextBytes(final byte[] bytes) {
        final GenerateRandomRequest request = new GenerateRandomRequest();
        request.setNumberOfBytes(bytes.length);
        final GenerateRandomResult result = kms.generateRandom(request);
        final ByteBuffer randomBytes = result.getPlaintext();
        randomBytes.get(bytes);
    }

    protected byte[] engineGenerateSeed(final int numBytes) {
        final byte[] retval = new byte[numBytes];
        engineNextBytes(retval);
        return retval;
    }

    protected AWSKMS getKms() {
        return kms;
    }

}