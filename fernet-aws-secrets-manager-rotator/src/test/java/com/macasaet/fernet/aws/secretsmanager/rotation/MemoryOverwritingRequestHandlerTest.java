/**
   Copyright 2019 Carlos Macasaet

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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.openMocks;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.DefaultRequest;
import com.amazonaws.Request;
import com.amazonaws.Response;
import com.amazonaws.http.HttpResponse;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.PutSecretValueResult;

public class MemoryOverwritingRequestHandlerTest {

    private AutoCloseable mockContext;
    private SecureRandom random;

    private MemoryOverwritingRequestHandler handler;

    @Before
    public void setUp() {
        mockContext = openMocks(this);

        random = new SecureRandom();
        handler = new MemoryOverwritingRequestHandler(random);
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public void verifyAfterResponseClearsSecret() {
        // given
        final ByteBuffer secretBinary = ByteBuffer.wrap(new byte[] { 1, 1, 2, 3, 5, 8 });
        assertTrue(Arrays.equals(secretBinary.array(), new byte[] { 1, 1, 2, 3, 5, 8}));
        final PutSecretValueRequest originalRequest = new PutSecretValueRequest();
        originalRequest.setSecretBinary(secretBinary);
        final Request<PutSecretValueRequest> request = new DefaultRequest<PutSecretValueRequest>(originalRequest,
                "AWSSecretsManager");
        final PutSecretValueResult result = mock(PutSecretValueResult.class);
        final HttpResponse httpResponse = mock(HttpResponse.class);
        final Response<PutSecretValueResult> response = new Response<PutSecretValueResult>(result, httpResponse);

        // when
        handler.afterResponse(request, response);

        // then
        assertFalse(Arrays.equals(secretBinary.array(), new byte[] { 1, 1, 2, 3, 5, 8}));
    }

    @Test
    public void verifyAfterErrorClearsSecret() {
        // given
        final ByteBuffer secretBinary = ByteBuffer.wrap(new byte[] { 1, 1, 2, 3, 5, 8 });
        assertTrue(Arrays.equals(secretBinary.array(), new byte[] { 1, 1, 2, 3, 5, 8}));
        final PutSecretValueRequest originalRequest = new PutSecretValueRequest();
        originalRequest.setSecretBinary(secretBinary);
        final Request<PutSecretValueRequest> request = new DefaultRequest<PutSecretValueRequest>(originalRequest,
                "AWSSecretsManager");
        final PutSecretValueResult result = mock(PutSecretValueResult.class);
        final HttpResponse httpResponse = mock(HttpResponse.class);
        final Response<PutSecretValueResult> response = new Response<PutSecretValueResult>(result, httpResponse);

        // when
        handler.afterError(request, response, new Exception());

        // then
        assertFalse(Arrays.equals(secretBinary.array(), new byte[] { 1, 1, 2, 3, 5, 8}));
    }

}