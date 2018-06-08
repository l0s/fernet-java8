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

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;

/**
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class RotationRequestTest {

    private ObjectMapper mapper;

    @Before
    public void setUp() throws Exception {
        mapper = new ObjectMapper().registerModule(new JaxbAnnotationModule());
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void verifyInputCorrectlyParsed() throws JsonParseException, JsonMappingException, IOException {
        // given
        final String version = "5244d77d-ab66-47cc-b207-0173bc721c12";
        final String arn = "arn:aws:secretsmanager:us-east-1:accountId:secret:secretName";
        final String step = "createSecret";
        final String json = "{"
            + "\"ClientRequestToken\": \"" + version + "\","
            + "\"SecretId\": \"" + arn + "\","
            + "\"Step\": \"" + step + "\""
            + "}";

        // when
        final RotationRequest result = mapper.readValue(json, RotationRequest.class);

        // then
        assertEquals(version, result.getClientRequestToken());
        assertEquals(arn, result.getSecretId());
        assertEquals(Step.CREATE_SECRET, result.getStep());
    }

}