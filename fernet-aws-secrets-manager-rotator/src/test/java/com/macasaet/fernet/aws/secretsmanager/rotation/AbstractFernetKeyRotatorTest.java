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

import static com.macasaet.fernet.aws.secretsmanager.rotation.Step.SET_SECRET;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.MockitoAnnotations.openMocks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Spy;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class AbstractFernetKeyRotatorTest {

    private AutoCloseable mockContext;
    @Spy
    private ObjectMapper mapper = new ObjectMapper().registerModule(new JaxbAnnotationModule());
    @Mock
    private SecretsManager secretsManager;
    @Mock
    private AWSKMS kms;

    @Mock
    private Spi randomSpi;
    @Mock
    private Provider.Service randomService;
    @Mock
    private Provider randomProvider;
    private SecureRandom random;

    private AbstractFernetKeyRotator rotator;

    @Captor
    private ArgumentCaptor<RotationRequest> requestCaptor;

    class Spi extends SecureRandomSpi {
        public void engineSetSeed(byte[] seed) {

        }
        public void engineNextBytes(byte[] bytes) {

        }
        public byte[] engineGenerateSeed(int numBytes) {
            return new byte[0];
        }
    }
    @Before
    public void setUp() throws Exception {
        mockContext = openMocks(this);
        final GenerateRandomResult randomResult = mock(GenerateRandomResult.class);
        given(randomResult.getPlaintext()).willReturn(ByteBuffer.allocate(1024));
        given(kms.generateRandom(any(GenerateRandomRequest.class))).willReturn(randomResult);

        given(randomService.newInstance(null)).willReturn(randomSpi);
        given(randomProvider.getService("SecureRandom", "mock")).willReturn(randomService);
        random = SecureRandom.getInstance("mock", randomProvider);
        rotator = new AbstractFernetKeyRotator(mapper, secretsManager, kms, random) {
            protected void testSecret(String secretId, String clientRequestToken) {
            }

            protected void createSecret(String secretId, String clientRequestToken) {
                getRandom().nextLong();
            }
        };
        rotator = spy(rotator);
    }

    @After
    public void tearDown() throws Exception {
        mockContext.close();
    }

    @Test
    public final void verifyHandleRequestDeserialisesRequest() throws IOException {
        // given
        final Context context = mock(Context.class);
        final String inputString = "{"
          + "\"SecretId\": \"secret\","
          + "\"ClientRequestToken\": \"token\","
          + "\"Step\": \"setSecret\""
          + "}";
        doNothing().when(rotator).handleRotationRequest(any(RotationRequest.class));

        try (ByteArrayInputStream input = new ByteArrayInputStream(inputString.getBytes("UTF-8"))) {
            try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                // when
                rotator.handleRequest(input, output, context);

                // then
                verify(rotator).handleRotationRequest(requestCaptor.capture());
                final RotationRequest result = requestCaptor.getValue();
                assertEquals("secret", result.getSecretId());
                assertEquals("token", result.getClientRequestToken());
                assertEquals(SET_SECRET, result.getStep());
            }
        }
    }

    @Test
    public final void verifyConditionallyCreateSecretSkipsCreation() throws UnsupportedEncodingException {
        // given
        given(secretsManager.getSecretVersion("secret", "version")).willReturn(ByteBuffer.wrap("key".getBytes("UTF-8")));

        // when
        rotator.conditionallyCreateSecret("secret", "version");

        // then
        verify(rotator, never()).createSecret("secret", "version");
    }

    @Test
    public final void verifyConditionallyCreateCreatesSecret() throws UnsupportedEncodingException {
        // given
        given(secretsManager.getSecretVersion("secret", "version")).willThrow(new ResourceNotFoundException("not found"));

        // when
        rotator.conditionallyCreateSecret("secret", "version");

        // then
        verify(rotator).createSecret("secret", "version");
    }

    @Test
    public final void verifyFinishSecretDoesNothing() {
        // given
        final Map<String, List<String>> versions = new HashMap<>();
        versions.put("version", singletonList("AWSCURRENT"));

        // when
        rotator.finishSecret("secret", "version", versions);

        // then
        verifyNoMoreInteractions(secretsManager);
    }

    @Test
    public final void verifyFinishSecretFails() {
        // given
        final Map<String, List<String>> versions = new HashMap<>();
        versions.put("version", singletonList("AWSPENDING"));

        // when / then (exception thrown)
        assertThrows(RuntimeException.class, () -> rotator.finishSecret("secret", "version", versions));
    }

    @Test
    public final void verifyFinishSecretRotatesSecret() {
        // given
        final Map<String, List<String>> versions = new HashMap<>();
        versions.put("newVersion", singletonList("AWSPENDING"));
        versions.put("oldVersion", singletonList("AWSCURRENT"));

        // when
        rotator.finishSecret("secret", "newVersion", versions);

        // then
        verify(secretsManager).rotateSecret("secret", "newVersion", "oldVersion");
    }

    @Test
    public final void verifySeedOnlyRunsOnce() {
        // given
        final GenerateRandomResult randomResult = new GenerateRandomResult();
        final byte[] bytes = new byte[512];
        Arrays.fill(bytes, (byte)17);
        randomResult.setPlaintext(ByteBuffer.wrap(bytes));
        given(kms.generateRandom(any(GenerateRandomRequest.class))).willReturn(randomResult);

        // when
        rotator.seed();
        rotator.seed();

        // then
        verify(randomSpi, times(1)).engineSetSeed(bytes);
    }

}