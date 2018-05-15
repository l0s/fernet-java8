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

import static java.util.Collections.singletonList;

import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

/**
 * AWS Lambda that rotates Fernet keys. To access a key, retrieve AWSCURRENT, AWSPENDING, or AWSPREVIOUS. To validate
 * and decrypt a token, it will be necessary to retrieve AWSCURRENT and AWSPENDING as there is no way to know which one
 * was used to generate the token.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class SimpleFernetKeyRotator extends AbstractFernetKeyRotator {

    protected void testSecret(final String secretId, final String clientRequestToken) {
        final GetSecretValueResult pendingSecretResult = getSecretVersionStage(secretId, clientRequestToken,
                "AWSPENDING");
        final Key key = new Key(pendingSecretResult.getSecretString());
        final Token token = Token.generate(getRandom(), key, "");
        if (!token.isValidSignature(key)) {
            throw new IllegalStateException("Pending key is unable to create and validate a Fernet token.");
        }
        // TODO log that secret was validated
    }

    protected void createSecret(final LambdaLogger logger, final String secretId, final String clientRequestToken) {
        assertCurrentStageExists(secretId, clientRequestToken);
        try {
            getSecretVersionStage(secretId, clientRequestToken, "AWSPENDING");
            logger.log("createSecret: Successfully retrieved secret for " + secretId + ". Doing nothing.");
        } catch( final ResourceNotFoundException rnfe ) {
            final Key key = Key.generateKey(getRandom());
            final PutSecretValueRequest putSecretValueRequest = new PutSecretValueRequest();
            putSecretValueRequest.setSecretId(secretId);
            putSecretValueRequest.setClientRequestToken(clientRequestToken);
            putSecretValueRequest.setSecretString(key.serialise());
            putSecretValueRequest.setVersionStages(singletonList("AWSPENDING"));
            getSecretsManager().putSecretValue(putSecretValueRequest);
            logger.log("createSecret: Successfully put secret for ARN " + secretId + " and version "
                    + clientRequestToken + ".");
        }
    }

}