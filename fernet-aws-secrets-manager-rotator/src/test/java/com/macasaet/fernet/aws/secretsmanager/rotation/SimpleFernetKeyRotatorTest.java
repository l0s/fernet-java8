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
package com.macasaet.fernet.aws.secretsmanager.rotation;

import static java.util.Collections.singletonList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.stream.IntStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.macasaet.fernet.Key;

public class SimpleFernetKeyRotatorTest {

    @Mock
    private LambdaLogger logger;
    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;
    @Mock
    private SecureRandom random;
    
    @InjectMocks
    private SimpleFernetKeyRotator rotator;

    @Before
    public void setUp() throws Exception {
        initMocks(this);
        final Answer<Void> loggingAnswer = new Answer<Void>() {
            public Void answer(final InvocationOnMock invocation) throws Throwable {
                final String message = invocation.getArgument(0);
                System.out.println("LAMBDA: " + message);
                return null;
            }
        };
        doAnswer(loggingAnswer).when(logger).log(anyString());
        final Answer<Void> nonRandomBytes = new Answer<Void>() {
            public Void answer(final InvocationOnMock invocation) throws Throwable {
                final byte[] bytes = invocation.getArgument(0);
                IntStream.range(0, bytes.length).parallel().forEach(i -> bytes[ i ] = 0);
                return null;
            }
        };
        doAnswer(nonRandomBytes).when(random).nextBytes(any(byte[].class));
        final Answer<GenerateRandomResult> nonRandomResult = new Answer<GenerateRandomResult>() {
            public GenerateRandomResult answer(final InvocationOnMock invocation) throws Throwable {
                final GenerateRandomRequest request = invocation.getArgument(0);
                final GenerateRandomResult retval = new GenerateRandomResult();
                retval.setPlaintext(ByteBuffer.allocateDirect(request.getNumberOfBytes()));
                return retval;
            }
        };
        given(kms.generateRandom(any(GenerateRandomRequest.class))).will(nonRandomResult);    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void verifyCreate() {
        // given
        final Context context = mock(Context.class);
        given(context.getLogger()).willReturn(logger);
        final String clientRequestToken = "clientRequestToken";
        final String secretId = "secretId";

        final DescribeSecretResult secretDescription = new DescribeSecretResult();
        secretDescription.setRotationEnabled(true);
        secretDescription.addVersionIdsToStagesEntry(clientRequestToken, singletonList("AWSPENDING"));
        given(secretsManager.describeSecret(secretId)).willReturn(secretDescription);
        given(secretsManager.getSecretVersionStage(secretId, clientRequestToken, "AWSPENDING")).willThrow(new ResourceNotFoundException("no value yet"));

        // when
        final Request creationRequest = new Request();
        creationRequest.setClientRequestToken(clientRequestToken);
        creationRequest.setSecretId(secretId);
        creationRequest.setStep(Step.CREATE_SECRET);
        rotator.handleRequest(creationRequest, context);

        // then
        verify(secretsManager).putSecretValue(eq("secretId"), eq(clientRequestToken), any(Key.class), eq("AWSPENDING"));
    }

}