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

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;

/**
 * Rotating an AWS Secrets Manager secret is a multi-step process. Each step will involve a separate invocation of the
 * rotation Lambda.
 *
 * <p>Copyright &copy; 2018 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@XmlType(name="step")
@XmlEnum
public enum Step {
    @XmlEnumValue("createSecret")
    CREATE_SECRET,
    @XmlEnumValue("setSecret")
    SET_SECRET,
    @XmlEnumValue("testSecret")
    TEST_SECRET,
    @XmlEnumValue("finishSecret")
    FINISH_SECRET
}