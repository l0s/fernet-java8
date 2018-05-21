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

import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.PENDING;
import static java.util.Collections.singletonList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import com.macasaet.fernet.Key;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class SimpleFernetKeyRotatorTest {

    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;
    @Mock
    private SecureRandom random;

    private ObjectMapper mapper;

    @InjectMocks
    private SimpleFernetKeyRotator rotator;

    @Before
    public void setUp() throws Exception {
        mapper = new ObjectMapper();
        mapper.registerModule(new JaxbAnnotationModule());
        initMocks(this);

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
        given(kms.generateRandom(any(GenerateRandomRequest.class))).will(nonRandomResult);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void verifyCreate() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String clientRequestToken = "clientRequestToken";
        final String secretId = "secretId";

        final DescribeSecretResult secretDescription = new DescribeSecretResult();
        secretDescription.setRotationEnabled(true);
        secretDescription.addVersionIdsToStagesEntry(clientRequestToken, singletonList("AWSPENDING"));
        given(secretsManager.describeSecret(secretId)).willReturn(secretDescription);
        given(secretsManager.getSecretVersionStage(secretId, clientRequestToken, PENDING))
                .willThrow(new ResourceNotFoundException("no value yet"));

        final RotationRequest creationRequest = new RotationRequest();
        creationRequest.setClientRequestToken(clientRequestToken);
        creationRequest.setSecretId(secretId);
        creationRequest.setStep(Step.CREATE_SECRET);
        final byte[] creationRequestBytes = mapper.writeValueAsBytes(creationRequest);

        // when
        try (InputStream input = new ByteArrayInputStream(creationRequestBytes)) {
            try (OutputStream output = new ByteArrayOutputStream()) {
                rotator.handleRequest(input, output, context);

                // then
                verify(secretsManager).putSecretValue(eq("secretId"), eq(clientRequestToken), any(Key.class),
                        eq(PENDING));
            }
        }
    }

}