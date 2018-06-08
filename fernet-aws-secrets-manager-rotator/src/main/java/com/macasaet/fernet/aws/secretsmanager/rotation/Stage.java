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

/**
 * The stage of a secret's lifecycle. When a new secret is created, it is first {@link #PENDING}. When it is activated,
 * it will be {@link #CURRENT}. The last current secret is available as {@link #PREVIOUS}.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
public enum Stage {

    CURRENT,
    PENDING,
    PREVIOUS;

    public String getAwsName() {
        return "AWS" + name();
    }

}