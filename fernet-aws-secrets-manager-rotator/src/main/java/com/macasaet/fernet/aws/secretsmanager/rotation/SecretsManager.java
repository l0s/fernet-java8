package com.macasaet.fernet.aws.secretsmanager.rotation;

import static java.util.Collections.singletonList;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.DescribeSecretRequest;
import com.amazonaws.services.secretsmanager.model.DescribeSecretResult;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.PutSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.UpdateSecretVersionStageRequest;
import com.macasaet.fernet.Key;

class SecretsManager {

    private final AWSSecretsManager delegate;

    protected SecretsManager(final AWSSecretsManager delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate cannot be null");
        }
        this.delegate = delegate;
    }

    protected void assertCurrentStageExists(final String secretId, final String clientRequestToken) {
        getSecretVersionStage(secretId, clientRequestToken, "AWSCURRENT");
    }

    public DescribeSecretResult describeSecret(final String secretId) {
        final DescribeSecretRequest describeSecretRequest = new DescribeSecretRequest();
        describeSecretRequest.setSecretId(secretId);
        return getDelegate().describeSecret(describeSecretRequest);
    }

    public GetSecretValueResult getSecretVersionStage(final String secretId, final String clientRequestToken,
            final String stage) {
        final GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest();
        getSecretValueRequest.setSecretId(secretId);
        getSecretValueRequest.setVersionId(clientRequestToken);
        getSecretValueRequest.setVersionStage(stage);
        return getDelegate().getSecretValue(getSecretValueRequest);
    }

    public void updateSecretVersionStage(final String secretId, final String clientRequestToken,
            String currentVersion) {
        final UpdateSecretVersionStageRequest updateSecretVersionStageRequest = new UpdateSecretVersionStageRequest();
        updateSecretVersionStageRequest.setSecretId(secretId);
        updateSecretVersionStageRequest.setMoveToVersionId(clientRequestToken);
        updateSecretVersionStageRequest.setRemoveFromVersionId(currentVersion);
        getDelegate().updateSecretVersionStage(updateSecretVersionStageRequest);
    }

    public void putSecretValue(final String secretId, final String clientRequestToken, final Key key, final String stage) {
        final PutSecretValueRequest putSecretValueRequest = new PutSecretValueRequest();
        putSecretValueRequest.setSecretId(secretId);
        putSecretValueRequest.setClientRequestToken(clientRequestToken);
        putSecretValueRequest.setSecretString(key.serialise());
        putSecretValueRequest.setVersionStages(singletonList(stage));
        getDelegate().putSecretValue(putSecretValueRequest);        
    }

    public void putSecretValue(final String secretId, final String clientRequestToken, final List<Key> keys, final String stage) {
        final PutSecretValueRequest putSecretValueRequest = new PutSecretValueRequest();
        putSecretValueRequest.setSecretId(secretId);
        putSecretValueRequest.setClientRequestToken(clientRequestToken);
        putSecretValueRequest.setVersionStages(singletonList("AWSPENDING"));
        try( ByteArrayOutputStream outputStream = new ByteArrayOutputStream(32 * keys.size()) ) {
            for( final Key key : keys ) {
                key.writeTo(outputStream);
            }
            // TODO: need to make sure encoding is compatible
            final String newSecret = Base64.getUrlEncoder().encodeToString( outputStream.toByteArray() );
            putSecretValueRequest.setSecretString(newSecret);
        } catch( final IOException ioe ) {
            // this really should not happen as I/O is to memory only
            throw new IllegalStateException(ioe.getMessage(), ioe);
        }
    
        getDelegate().putSecretValue(putSecretValueRequest);
    }

    protected AWSSecretsManager getDelegate() {
        return delegate;
    }

}