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
package com.macasaet.fernet.example.rotation.aws;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.DescribeSecretRequest;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.UpdateSecretVersionStageRequest;

public abstract class AbstractFernetKeyRotator implements RequestHandler<Request, Void> {

    private final AWSSecretsManager secretsManager = AWSSecretsManagerClientBuilder.defaultClient();
    private final AWSKMS kms = AWSKMSClientBuilder.defaultClient();
    private final SecureRandomSpi randomServiceProvider = new KmsSecureRandomServiceProvider(kms);
    private final Random random = new SecureRandom(randomServiceProvider, null) {
        private static final long serialVersionUID = 1069780566700570443L;
    };

    public Void handleRequest(final Request request, final Context context) {
        final LambdaLogger logger = context.getLogger();
        final String secretId = request.getSecretId();
        final String clientRequestToken = request.getClientRequestToken();
    
        final DescribeSecretResult secretMetadata = describeSecret(secretId);
        if (secretMetadata.isRotationEnabled() == null || !secretMetadata.isRotationEnabled()) {
            throw new IllegalArgumentException("Secret " + secretId + " is not enabled for rotation.");
        }
        final Map<String, List<String>> versions = secretMetadata.getVersionIdsToStages();
        
        if (!versions.containsKey(clientRequestToken)) {
            throw new IllegalArgumentException("Secret version " + clientRequestToken
                    + " has no stage for rotation of secret " + secretId + ".");
        }
    
        final List<String> stages = versions.get(clientRequestToken);
        if (stages.contains("AWSCURRENT")) {
            logger.log("Secret version " + clientRequestToken
                    + " already set as AWSCURRENT for secret " + secretId + ". Doing nothing.");
            return null;
        } else if (!stages.contains("AWSPENDING")) {
            throw new IllegalArgumentException("Secret version " + clientRequestToken
                    + " not set as AWSPENDING for rotation of secret " + secretId + ".");
        }
        switch (request.getStep()) {
            case CREATE_SECRET:
                createSecret(logger, secretId, clientRequestToken);
                return null;
            case FINISH_SECRET:
                String currentVersion = null;
                for( final String versionId : versions.keySet() ) {
                    final List<String> versionStages = versions.get(versionId);
                    if( versionStages.contains("AWSCURRENT") ) {
                        if( versionId.equals(clientRequestToken ) ) {
                            // The correct version is already marked as current, return
                            logger.log("finishSecret: Version " + versionId
                    + " already marked as AWSCURRENT for " + secretId + "");
                            return null;
                        }
                        currentVersion = versionId;
                        break;
                    }
                }
                if (currentVersion == null) {
                    throw new IllegalStateException("No AWSCURRENT secret set for " + secretId + ".");
                }
                final UpdateSecretVersionStageRequest updateSecretVersionStageRequest = new UpdateSecretVersionStageRequest();
                updateSecretVersionStageRequest.setSecretId(secretId);
                updateSecretVersionStageRequest.setMoveToVersionId(clientRequestToken);
                updateSecretVersionStageRequest.setRemoveFromVersionId(currentVersion);
                getSecretsManager().updateSecretVersionStage(updateSecretVersionStageRequest);
                logger.log("finishSecret: Successfully set AWSCURRENT stage to version " + clientRequestToken
                        + " for secret " + secretId + ".");
                return null;
            case SET_SECRET:
                // not applicable
                return null;
            case TEST_SECRET:
                testSecret(secretId, clientRequestToken);
                return null;
            default:
                throw new IllegalArgumentException("Missing or invalid step provided");
        }
    }

    protected abstract void testSecret(String secretId, String clientRequestToken);

    protected abstract void createSecret(LambdaLogger logger, String secretId, String clientRequestToken);

    protected void assertCurrentStageExists(final String secretId, final String clientRequestToken) {
        getSecretVersionStage(secretId, clientRequestToken, "AWSCURRENT");
    }

    protected GetSecretValueResult getSecretVersionStage(final String secretId, final String clientRequestToken, final String stage) {
        final GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest();
        getSecretValueRequest.setSecretId(secretId);
        getSecretValueRequest.setVersionId(clientRequestToken);
        getSecretValueRequest.setVersionStage(stage);
        return getSecretsManager().getSecretValue(getSecretValueRequest);
    }

    protected DescribeSecretResult describeSecret(final String secretId) {
        final DescribeSecretRequest describeSecretRequest = new DescribeSecretRequest();
        describeSecretRequest.setSecretId(secretId);
        return getSecretsManager().describeSecret(describeSecretRequest);
    }

    protected AWSSecretsManager getSecretsManager() {
        return secretsManager;
    }

    protected Random getRandom() {
        return random;
    }

}