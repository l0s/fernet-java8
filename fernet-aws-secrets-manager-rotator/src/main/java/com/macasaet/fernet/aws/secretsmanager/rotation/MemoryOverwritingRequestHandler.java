/**
   Copyright 2019 Carlos Macasaet

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
package com.macasaet.fernet.aws.secretsmanager.rotation;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import com.amazonaws.Request;
import com.amazonaws.Response;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;

/**
 * This request handler makes a best effort to clear out sensitive data that was submitted to the AWS SDK after any
 * response or error. The scope is limited to request objects. It does not account for any copies that may have been
 * made by the SDK (e.g. by the marshalling process) nor any copies made by the JVM.
 *
 * <p>Copyright &copy; 2019 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
class MemoryOverwritingRequestHandler extends RequestHandler2 {

    private final SecureRandom random;

    public MemoryOverwritingRequestHandler(final SecureRandom random) {
        super();
        if (random == null) {
            throw new IllegalArgumentException("random cannot be null");
        }
        this.random = random;
    }

    public void afterResponse(final Request<?> request, final Response<?> response) {
        final Object requestObject = request.getOriginalRequestObject();
        if (requestObject instanceof PutSecretValueRequest) {
            final PutSecretValueRequest putRequest = (PutSecretValueRequest) requestObject;
            overwriteSecret(putRequest);
        }
    }

    public void afterError(final Request<?> request, final Response<?> response, final Exception exception) {
        final Object requestObject = request.getOriginalRequestObject();
        if (requestObject instanceof PutSecretValueRequest) {
            final PutSecretValueRequest putRequest = (PutSecretValueRequest) requestObject;
            overwriteSecret(putRequest);
        }
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    protected void overwriteSecret(final PutSecretValueRequest putRequest) {
        final ByteBuffer buffer = putRequest.getSecretBinary();
        final byte[] bytes = new byte[buffer.capacity()];
        getRandom().nextBytes(bytes);
        ((Buffer)buffer).clear();
        buffer.put(bytes);
    }

    protected SecureRandom getRandom() {
        return random;
    }

}