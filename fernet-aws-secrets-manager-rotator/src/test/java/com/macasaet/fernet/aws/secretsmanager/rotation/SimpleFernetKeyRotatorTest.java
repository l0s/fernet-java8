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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.openMocks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Arrays;
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

    private AutoCloseable mockContext;
    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;
    private SecureRandomSpi randomSpi;
    @Mock
    private Provider.Service randomService;
    @Mock
    private Provider randomProvider;
    private SecureRandom random;

    private ObjectMapper mapper;

    private SimpleFernetKeyRotator rotator;

    @Before
    public void setUp() throws Exception {
        mockContext = openMocks(this);
        mapper = new ObjectMapper();
        mapper.registerModule(new JaxbAnnotationModule());

        randomSpi = new SecureRandomSpi() {
            protected void engineSetSeed(byte[] seed) {
            }

            protected void engineNextBytes(byte[] bytes) {
                IntStream.range(0, bytes.length).parallel().forEach(i -> bytes[ i ] = 0);
            }

            protected byte[] engineGenerateSeed(int numBytes) {
                final byte[] result = new byte[numBytes];
                engineNextBytes(result);
                return result;
            }
        };

        given(randomService.newInstance(null)).willReturn(randomSpi);
        given(randomProvider.getService("SecureRandom", "mock")).willReturn(randomService);
        random = SecureRandom.getInstance("mock", randomProvider);

        final Answer<GenerateRandomResult> nonRandomResult = invocation -> {
            final GenerateRandomRequest request = invocation.getArgument(0);
            final GenerateRandomResult retval = new GenerateRandomResult();
            retval.setPlaintext(ByteBuffer.allocateDirect(request.getNumberOfBytes()));
            return retval;
        };
        given(kms.generateRandom(any(GenerateRandomRequest.class))).will(nonRandomResult);

        rotator = new SimpleFernetKeyRotator(secretsManager, kms, random);
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public void verifyHandleRequestCreatesKey() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String clientRequestToken = "clientRequestToken";
        final String secretId = "secretId";

        final DescribeSecretResult secretDescription = new DescribeSecretResult();
        secretDescription.setRotationEnabled(true);
        secretDescription.addVersionIdsToStagesEntry(clientRequestToken, singletonList("AWSPENDING"));
        given(secretsManager.describeSecret(secretId)).willReturn(secretDescription);
        given(secretsManager.getSecretVersion(secretId, clientRequestToken))
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

    @Test
    public final void verifyHandleRequestTestsValidKey() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String clientRequestToken = "clientRequestToken";
        final String secretId = "secretId";

        final DescribeSecretResult secretDescription = new DescribeSecretResult();
        secretDescription.setRotationEnabled(true);
        secretDescription.addVersionIdsToStagesEntry(clientRequestToken, singletonList("AWSPENDING"));
        given(secretsManager.describeSecret(secretId)).willReturn(secretDescription);

        final Key key = Key.generateKey(random);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(32)) {
            key.writeTo(outputStream);
            given(secretsManager.getSecretVersion(secretId, clientRequestToken))
                    .willReturn(ByteBuffer.wrap(outputStream.toByteArray()));
        }

        final RotationRequest testRequest = new RotationRequest();
        testRequest.setClientRequestToken(clientRequestToken);
        testRequest.setSecretId(secretId);
        testRequest.setStep(Step.TEST_SECRET);
        final byte[] testRequestBytes = mapper.writeValueAsBytes(testRequest);

        try( InputStream input = new ByteArrayInputStream(testRequestBytes) ) {
            try( OutputStream output = new ByteArrayOutputStream() ) {
                // when
                rotator.handleRequest(input, output, context);

                // then (nothing)
            }
        }
    }

    @Test
    public final void verifyHandleRequestTestsInsufficientBytes() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String clientRequestToken = "clientRequestToken";
        final String secretId = "secretId";

        final DescribeSecretResult secretDescription = new DescribeSecretResult();
        secretDescription.setRotationEnabled(true);
        secretDescription.addVersionIdsToStagesEntry(clientRequestToken, singletonList("AWSPENDING"));
        given(secretsManager.describeSecret(secretId)).willReturn(secretDescription);

        given(secretsManager.getSecretVersion(secretId, clientRequestToken)).willReturn(ByteBuffer.allocateDirect(31));

        final RotationRequest testRequest = new RotationRequest();
        testRequest.setClientRequestToken(clientRequestToken);
        testRequest.setSecretId(secretId);
        testRequest.setStep(Step.TEST_SECRET);
        final byte[] testRequestBytes = mapper.writeValueAsBytes(testRequest);

        try( InputStream input = new ByteArrayInputStream(testRequestBytes) ) {
            try( OutputStream output = new ByteArrayOutputStream() ) {
                // when / then (exception thrown)
                assertThrows(RuntimeException.class, () -> rotator.handleRequest(input, output, context));
            }
        }
    }

    @Test
    public final void verifyHandleRequestTestsTooManyBytes() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String clientRequestToken = "clientRequestToken";
        final String secretId = "secretId";

        final DescribeSecretResult secretDescription = new DescribeSecretResult();
        secretDescription.setRotationEnabled(true);
        secretDescription.addVersionIdsToStagesEntry(clientRequestToken, singletonList("AWSPENDING"));
        given(secretsManager.describeSecret(secretId)).willReturn(secretDescription);

        given(secretsManager.getSecretVersion(secretId, clientRequestToken)).willReturn(ByteBuffer.allocateDirect(33));

        final RotationRequest testRequest = new RotationRequest();
        testRequest.setClientRequestToken(clientRequestToken);
        testRequest.setSecretId(secretId);
        testRequest.setStep(Step.TEST_SECRET);
        final byte[] testRequestBytes = mapper.writeValueAsBytes(testRequest);

        try( InputStream input = new ByteArrayInputStream(testRequestBytes) ) {
            try( OutputStream output = new ByteArrayOutputStream() ) {
                // when / then (exception thrown)
                assertThrows(RuntimeException.class, () -> rotator.handleRequest(input, output, context));
            }
        }
    }

    @Test
    public final void verifyTestClearsIntermediateSecret() {
        // given
        final byte[] secretBytes = new byte[32];
        for (byte i = 32; --i >= 0; secretBytes[i] = i);
        final ByteBuffer secretByteBuffer = ByteBuffer.wrap(secretBytes);
        assertTrue(Arrays.equals(secretByteBuffer.array(), secretBytes));
        given(secretsManager.getSecretVersion("secretId", "clientRequestToken")).willReturn(secretByteBuffer);

        // when
        rotator.testSecret("secretId", "clientRequestToken");

        // then
        final byte[] modifiedBytes = secretByteBuffer.array();
        assertEquals(32, modifiedBytes.length);
        for (int i = modifiedBytes.length; --i >= 0; assertEquals(0, modifiedBytes[i]));
    }

}