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
package com.macasaet.fernet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

import java.nio.charset.Charset;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;

/**
 * This contains common values used throughout the framework.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 * @author Carlos Macasaet
 */
interface Constants {

    Charset charset = UTF_8;
    Encoder encoder = getUrlEncoder();
    Decoder decoder = getUrlDecoder();
    /**
     * The algorithm used to encrypt the token contents.
     */
    String encryptionAlgorithm = "AES";
    /**
     * The algorithm used to sign the token.
     */
    String signingAlgorithm = "HmacSHA256";
    /**
     * The number of bytes used to store the encryption initialisation vector
     */
    int initializationVectorBytes = 16;
    /**
     * The number of bytes used to store the timestamp of a Fernet token.
     */
    int timestampBytes = 8;
    /**
     * The number of bytes used to indicate the version of a Fernet token.
     */
    int versionBytes = 1;
    /**
     * The number of bytes before the cipher text portion of a Fernet token.
     */
    int tokenPrefixBytes = versionBytes + timestampBytes + initializationVectorBytes;
    /**
     * The number of bytes in a valid signing key.
     */
    int signingKeyBytes = 16;
    /**
     * The number of bytes in a valid encryption key.
     */
    int encryptionKeyBytes = 16;
    /**
     * The total number of bytes in a valid Fernet key.
     */
    int fernetKeyBytes = signingKeyBytes + encryptionKeyBytes;
    /**
     * The AES block size used by the cipher.
     */
    int cipherTextBlockSize = 16;
    /**
     * The transformation (algorithm, mode, and padding) used by the cipher.
     * 
     * @see Cipher#getInstance(String)
     */
    String cipherTransformation = encryptionAlgorithm + "/CBC/PKCS5Padding";
    /**
     * The number of bytes for the HMAC signature.
     */
    int signatureBytes = 32;
    /**
     * The Fernet token version supported by this library.
     */
    byte supportedVersion = (byte) 0x80;
    /**
     * The number of bytes in the static portion of the token (excludes cipher text).
     */
    int tokenStaticBytes = versionBytes + timestampBytes + initializationVectorBytes + signatureBytes;
    /**
     * The minimum number of bytes in a token (i.e. with an empty plaintext).
     */
    int minimumTokenBytes = tokenStaticBytes + cipherTextBlockSize;

}