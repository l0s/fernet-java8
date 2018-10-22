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

import javax.xml.bind.annotation.XmlAttribute;

/**
 * A request from AWS Secrets Manager to rotate a secret.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class RotationRequest {

    @XmlAttribute(name = "SecretId", required = true)
    private String secretId;
    @XmlAttribute(name = "ClientRequestToken", required = true)
    private String clientRequestToken;
    @XmlAttribute(name = "Step", required = true)
    private Step step;

    /**
     * @return the ARN of the Secrets Manager secret in the form arn:aws:secretsmanager:{region}:{account}:secret:{secret-name}.
     */
    public String getSecretId() {
        return secretId;
    }

    /**
     * @param secretId the ARN of the Secrets Manager secret in the form arn:aws:secretsmanager:{region}:{account}:secret:{secret-name}.
     */
    public void setSecretId(final String secretId) {
        this.secretId = secretId;
    }

    /**
     * @return a unique identifier for this rotation operation, which will span multiple requests. This is typically a UUID.
     */
    public String getClientRequestToken() {
        return clientRequestToken;
    }

    /**
     * @param clientRequestToken a unique identifier for this rotation operation, which will span multiple requests. This is typically a UUID.
     */
    public void setClientRequestToken(final String clientRequestToken) {
        this.clientRequestToken = clientRequestToken;
    }

    /**
     * @return the phase of the rotation process
     * @see Step
     */
    public Step getStep() {
        return step;
    }

    /**
     * @param step the phase of the rotation process
     * @see Step
     */
    public void setStep(final Step step) {
        this.step = step;
    }

    public String toString() {
        final StringBuilder builder = new StringBuilder(256);
        builder.append("RotationRequest [SecretId=")
            .append(getSecretId())
            .append(", ClientRequestToken=")
            .append(getClientRequestToken())
            .append(", Step=")
            .append(getStep())
            .append(']');
        return builder.toString();
    }

}