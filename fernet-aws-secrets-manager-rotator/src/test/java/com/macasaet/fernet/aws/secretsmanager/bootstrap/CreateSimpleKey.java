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
 * Utility to generate a single Fernet key to store in AWS Secrets Manager.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public class CreateSimpleKey {

    public static final void main(final String... args) throws Exception {
        final SecureRandom random = new SecureRandom();
        final Key key = Key.generateKey(random);
        try (FileOutputStream outputStream = new FileOutputStream("simple-key")) {
            key.writeTo(outputStream);
        }
        /*
          aws secretsmanager create-secret --name simple-fernet-key --secret-binary fileb://simple-key
          {
               "ARN": "arn:aws:secretsmanager:<region>:<account_id>:secret:simple-fernet-key-<random_value>",
               "Name": "simple-fernet-key",
               "VersionId": "<uuidv4>"
           }
         */
    }

}