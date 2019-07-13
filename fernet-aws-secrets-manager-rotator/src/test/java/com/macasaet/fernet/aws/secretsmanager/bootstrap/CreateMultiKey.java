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
package com.macasaet.fernet.aws.secretsmanager.bootstrap;

import java.io.FileOutputStream;
import java.security.SecureRandom;

import com.macasaet.fernet.Key;

/**
 * Utility to generate multiple Fernet keys to store in AWS Secrets Manager.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class CreateMultiKey {

    public static final void main(final String... arguments) throws Exception {
        final SecureRandom random = new SecureRandom();

        try (FileOutputStream outputStream = new FileOutputStream("multi-key")) {
            for (int i = 3; --i >= 0;) {
                final Key key = Key.generateKey(random);
                key.writeTo(outputStream);
            }
        }
        /*
            aws secretsmanager create-secret --name multi-fernet-key --secret-binary fileb://multi-key 
            {
                "ARN": "arn:aws:secretsmanager:<region>:<account_id>:secret:multi-fernet-key-<random_value>",
                "Name": "multi-fernet-key",
                "VersionId": "<uuidv4>"
            }
         */
    }

}