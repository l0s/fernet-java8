/**
   Copyright 2018 Carlos Macasaet

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
package com.macasaet.fernet.example.rotation.aws;

import static java.util.Collections.singletonList;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.StringValidator;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

/**
 * This rotator can be used when an array of Fernet keys is stored in AWSCURRENT. 
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class MultiFernetKeyRotator extends AbstractFernetKeyRotator {

    private static final Validator<String> validator = new StringValidator() {
    };
    private int maxActiveKeys = 3;

    public MultiFernetKeyRotator() {
        // TODO retrieve max active keys from system property
    }

    protected void testSecret(final String secretId, final String clientRequestToken) {
        final GetSecretValueResult pendingSecretResult = getSecretVersionStage(secretId, clientRequestToken,
                "AWSPENDING");
        final String string = pendingSecretResult.getSecretString();
        final byte[] bytes = Base64.getUrlDecoder().decode(string);
        if (bytes.length % 32 != 0) {
            throw new IllegalStateException("There must be a multiple of 32 bytes.");
        }
        // first key will become the staged key
        final Key candidateStagedKey = new Key(Arrays.copyOfRange(bytes, 0, 32)) {
        };
        // second key will become the primary key
        final Key candidatePrimaryKey = new Key(Arrays.copyOfRange(bytes, 32, 64)) {
        };
        Token.generate(getRandom(), candidateStagedKey, "").validateAndDecrypt(candidateStagedKey, validator);
        Token.generate(getRandom(), candidatePrimaryKey, "").validateAndDecrypt(candidatePrimaryKey, validator);
    }

    protected void createSecret(final LambdaLogger logger, final String secretId, final String clientRequestToken) {
        assertCurrentStageExists(secretId, clientRequestToken);
        try {
            getSecretVersionStage(secretId, clientRequestToken, "AWSPENDING");
            logger.log("createSecret: Successfully retrieved secret for " + secretId + ". Doing nothing.");
        } catch( final ResourceNotFoundException rnfe ) {
            final GetSecretValueResult current = getSecretVersionStage(secretId, clientRequestToken, "AWSCURRENT");
            final String currentActiveKeysBase64 = current.getSecretString();
            final byte[] currentActiveKeyBytes = Base64.getUrlDecoder().decode(currentActiveKeysBase64);
            if (currentActiveKeyBytes.length % 32 != 0) {
                throw new IllegalStateException("There must be a multiple of 32 bytes.");
            }
            final int numKeys = currentActiveKeyBytes.length / 32;
            List<Key> keys = new ArrayList<>(numKeys + 1);
            for( int i = 0; i < currentActiveKeyBytes.length; i += 32 ) {
                final Key key = new Key(Arrays.copyOfRange(currentActiveKeyBytes, i, i + 32) ) {};
                keys.add(key);
            }
            final Key keyToStage = Key.generateKey(getRandom());
            keys.add(0, keyToStage);
            if( keys.size() > getMaxActiveKeys() ) {
                keys = keys.subList(0, getMaxActiveKeys());
            }
            final PutSecretValueRequest putSecretValueRequest = new PutSecretValueRequest();
            putSecretValueRequest.setSecretId(secretId);
            putSecretValueRequest.setClientRequestToken(clientRequestToken);
            putSecretValueRequest.setVersionStages(singletonList("AWSPENDING"));
            try( ByteArrayOutputStream outputStream = new ByteArrayOutputStream(32 * getMaxActiveKeys()) ) {
                for( final Key key : keys ) {
                    key.writeTo(outputStream);
                }
                final String newSecret = Base64.getUrlEncoder().encodeToString( outputStream.toByteArray() );
                putSecretValueRequest.setSecretString(newSecret);
            } catch( final IOException ioe ) {
                // this really should not happen as I/O is to memory only
                throw new RuntimeException(ioe.getMessage(), ioe);
            }

            getSecretsManager().putSecretValue(putSecretValueRequest);
            logger.log("createSecret: Successfully put secret for ARN " + secretId + " and version "
                    + clientRequestToken + ".");
        }
    }

    protected int getMaxActiveKeys() {
        return maxActiveKeys;
    }

    protected void setMaxActiveKeys(int maxActiveKeys) {
        this.maxActiveKeys = maxActiveKeys;
    }

}