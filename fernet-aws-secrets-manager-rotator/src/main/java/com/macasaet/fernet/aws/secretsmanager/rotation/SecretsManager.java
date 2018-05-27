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

import static com.macasaet.fernet.aws.secretsmanager.rotation.Stage.CURRENT;
import static java.util.Collections.singletonList;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collection;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.DescribeSecretRequest;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.UpdateSecretVersionStageRequest;
import com.macasaet.fernet.Key;

/**
 * <p>Service façade for AWS Secrets Manager.</p>
 *
 * <p>This requires the following permissions: <code>secretsmanager:DescribeSecret</code>,
 * <code>secretsmanager:GetSecretValue</code>, <code>secretsmanager:UpdateSecretVersionStage</code>, and
 * <code>secretsmanager:PutSecretValue</code>.</p>
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * 
 * @author Carlos Macasaet
 */
class SecretsManager {

    private final AWSSecretsManager delegate;

    protected SecretsManager(final AWSSecretsManager delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate cannot be null");
        }
        this.delegate = delegate;
    }

    /**
     * This requires the permission <code>secretsmanager:GetSecretValue</code>
     *
     * @param secretId TODO
     */
    public void assertCurrentStageExists(final String secretId) {
        final GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest();
        getSecretValueRequest.setSecretId(secretId);
        getSecretValueRequest.setVersionStage(CURRENT.getAwsName());
        getDelegate().getSecretValue(getSecretValueRequest);
    }

    /**
     * This requires the permission <code>secretsmanager:DescribeSecret</code>
     *
     * @param secretId TODO
     * @return TODO
     */
    public DescribeSecretResult describeSecret(final String secretId) {
        final DescribeSecretRequest describeSecretRequest = new DescribeSecretRequest();
        describeSecretRequest.setSecretId(secretId);
        return getDelegate().describeSecret(describeSecretRequest);
    }

    /**
     * This requires the permission <code>secretsmanager:GetSecretValue</code>
     *
     * @param secretId TODO
     * @param clientRequestToken TODO
     * @param stage TODO
     * @return TODO
     */
    public GetSecretValueResult getSecretVersionStage(final String secretId, final String clientRequestToken,
            final Stage stage) {
        final GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest();
        getSecretValueRequest.setSecretId(secretId);
        getSecretValueRequest.setVersionId(clientRequestToken);
        getSecretValueRequest.setVersionStage(stage.getAwsName());
        return getDelegate().getSecretValue(getSecretValueRequest);
    }

    /**
     * This requires the permission <code>secretsmanager:UpdateSecretVersionStage</code>
     *
     * @param secretId TODO
     * @param clientRequestToken the version ID to be made "current"
     * @param currentVersion the current active version ID to be made "previous"
     */
    public void rotateSecret(final String secretId, final String clientRequestToken,
            String currentVersion) {
        final UpdateSecretVersionStageRequest updateSecretVersionStageRequest = new UpdateSecretVersionStageRequest();
        updateSecretVersionStageRequest.setSecretId(secretId);
        updateSecretVersionStageRequest.setVersionStage(CURRENT.getAwsName());
        updateSecretVersionStageRequest.setMoveToVersionId(clientRequestToken);
        updateSecretVersionStageRequest.setRemoveFromVersionId(currentVersion);
        getDelegate().updateSecretVersionStage(updateSecretVersionStageRequest);
    }

    /**
     * This requires the permission <code>secretsmanager:PutSecretValue</code>
     *
     * @param secretId TODO
     * @param clientRequestToken TODO
     * @param key TODO
     * @param stage TODO
     */
    public void putSecretValue(final String secretId, final String clientRequestToken, final Key key, final Stage stage) {
        putSecretValue(secretId, clientRequestToken, singletonList(key), stage);
    }

    /**
     * This requires the permission <code>secretsmanager:PutSecretValue</code>
     *
     * @param secretId TODO
     * @param clientRequestToken TODO
     * @param keys TODO
     * @param stage TODO
     */
    public void putSecretValue(final String secretId, final String clientRequestToken, final Collection<? extends Key> keys,
            final Stage stage) {
        final PutSecretValueRequest putSecretValueRequest = new PutSecretValueRequest();
        putSecretValueRequest.setSecretId(secretId);
        putSecretValueRequest.setClientRequestToken(clientRequestToken);
        putSecretValueRequest.setVersionStages(singletonList(stage.getAwsName()));
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(32 * keys.size())) {
            for (final Key key : keys) {
                key.writeTo(outputStream);
            }
            final ByteBuffer buffer = ByteBuffer.wrap(outputStream.toByteArray());
            putSecretValueRequest.setSecretBinary(buffer);
        } catch (final IOException ioe) {
            // this really should not happen as I/O is to memory only
            throw new IllegalStateException(ioe.getMessage(), ioe);
        }

        getDelegate().putSecretValue(putSecretValueRequest);
    }

    protected AWSSecretsManager getDelegate() {
        return delegate;
    }

}