/**
 Copyright 2017-2021 Carlos Macasaet

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
package com.macasaet.fernet.jersey.example.common;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Singleton;

import net.bytebuddy.utility.RandomString;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * A service for checking and setting user passwords.
 *
 * <p>Copyright &copy; 2017-2022 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
@Singleton
public class PasswordService {

    private static final Charset charset = StandardCharsets.UTF_8;
    private static final SecureRandom random = new SecureRandom();
    private static final Base64.Encoder encoder = Base64.getEncoder();

    private final User fakeUser;

    @Inject
    private UserRepository repository;

    {
        fakeUser = new User("placeholder", false, "");
        fakeUser.setPasswordHash(RandomString.make(32));
    }

    /**
     * Find the user and verify that the correct password was provided. This method should take the same amount of time
     * regardless of whether a valid username or the correct password are provided.
     *
     * @param username the unique User identifier
     * @param password the plain text password
     * @return the corresponding User if the username is valid and the password is correct or else null
     */
    public User authenticateUser(final String username, final CharSequence password) {
        final User user = repository.findUser(username);
        if(user != null) {
            if(isPasswordCorrect(user, password)) {
                return user;
            }
        } else {
            // ensure the same amount of time is taken in case the username is not valid
            isPasswordCorrect(fakeUser, password);
        }
        return null;
    }

    /**
     * Convert a plain text password into a hash in PHC format
     *
     * @param newPassword the user's new desired password in plain text
     * @return the password hash, salt, and parameters in PHC format
     */
    public CharSequence hashPassword(final CharSequence newPassword) {
        final byte[] salt = new byte[16];
        random.nextBytes(salt);
        final int iterations = 48;
        final int memoryAsKb = 4096;
        final int parallelism = 8;
        final Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(iterations)
                .withMemoryAsKB(memoryAsKb)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
        final Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        final char[] plainTextPassword = new char[newPassword.length()];
        for(int i = newPassword.length(); --i >= 0; plainTextPassword[i] = newPassword.charAt(i));
        final byte[] hash = new byte[32];
        generator.generateBytes(plainTextPassword, hash);
        final String memoryString = Integer.toString(memoryAsKb);
        final String iterationsString = Integer.toString(iterations);
        final String parallelismString = Integer.toString(parallelism);
        final ByteBuffer encodedSaltBytes = ByteBuffer.wrap(encoder.encode(salt));
        final CharBuffer encodedSaltChars = stripPadding(charset.decode(encodedSaltBytes));
        final ByteBuffer encodedHashBytes = ByteBuffer.wrap(encoder.encode(hash));
        final CharBuffer encodedHashChars = stripPadding(charset.decode(encodedHashBytes));

        final CharBuffer result = CharBuffer.allocate(1 + 8 + 5 + 3
                + memoryString.length() + 3 + iterationsString.length() + 3 + parallelismString.length()
                + 1 + encodedSaltChars.length() + 1 + encodedHashChars.length());
        result.append('$');
        result.append("argon2id");
        result.append("$v=19");
        result.append("$m=").append(memoryString);
        result.append("$t=").append(iterationsString);
        result.append("$p=").append(parallelismString);
        result.append('$').append(encodedSaltChars);
        result.append('$').append(encodedHashChars);
        result.limit(result.position());
        result.position(0);

        random.nextBytes(encodedHashBytes.array());
        random.nextBytes(hash);
        random.nextBytes(encodedSaltBytes.array());
        random.nextBytes(salt);
        encodedHashChars.position(0);
        encodedHashChars.put(RandomString.make(encodedHashChars.length()));
        encodedSaltChars.position(0);
        encodedSaltChars.put(RandomString.make(encodedSaltChars.length()));

        return result;
    }

    /**
     * @param plainTextPassword the password as provided by the client
     * @return true if and only if the password is correct
     */
    public boolean isPasswordCorrect(final User user, final CharSequence plainTextPassword) {
        final CharSequence phc = user.getPasswordHash();
        final CharSequence[] hashComponents = split(phc);
        int componentIndex = 0;
        if (hashComponents[componentIndex].length() != 0) {
            throw new IllegalStateException("Invalid password PHC component at index: " + componentIndex);
        }
        componentIndex++;
        final int algorithmId = getAlgorithmId(hashComponents[componentIndex]);
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(algorithmId);
        componentIndex++;
        final Map<String, String> workParameters = new HashMap<>();
        boolean processedSalt = false;
        final Collection<? extends String> requiredParameters = Arrays.asList("m", "t", "p");
        byte[] hash = null;
        while (componentIndex < hashComponents.length) {
            final CharSequence component = hashComponents[componentIndex];
            final int equalsIndex = indexOfAssignmentOperator(component);
            if (equalsIndex < 0) {
                // not a work parameter
                if (!processedSalt) {
                    final CharBuffer charBuffer = CharBuffer.wrap(component);
                    final ByteBuffer byteBuffer = charset.encode(charBuffer);
                    final ByteBuffer saltBuffer = Base64.getDecoder().decode(byteBuffer);
                    builder = builder.withSalt(saltBuffer.array());
                    processedSalt = true;
                } else {
                    final CharBuffer charBuffer = CharBuffer.wrap(component);
                    final ByteBuffer byteBuffer = charset.encode(charBuffer);
                    final ByteBuffer hashBuffer = Base64.getDecoder().decode(byteBuffer);
                    hash = hashBuffer.array();
                }
            } else {
                // work parameter
                final String key = component.subSequence(0, equalsIndex).toString();
                final String value = component.subSequence(equalsIndex + 1, component.length()).toString();
                workParameters.put(key, value);
            }
            componentIndex++;

            if (workParameters.keySet().containsAll(requiredParameters)
                    && processedSalt && hash != null) {
                break;
            }
        }
        if (!workParameters.containsKey("m")) {
            throw new IllegalStateException("PHC is missing memory parameter");
        }
        builder = builder.withMemoryAsKB(Integer.parseInt(workParameters.get("m")));
        if (!workParameters.containsKey("t")) {
            throw new IllegalArgumentException("PHC is missing iterations parameter");
        }
        builder = builder.withIterations(Integer.parseInt(workParameters.get("t")));
        if (!workParameters.containsKey("p")) {
            throw new IllegalArgumentException("PHC is missing parallelism parameter");
        }
        builder = builder.withParallelism(Integer.parseInt(workParameters.get("p")));
        final Argon2Parameters parameters = builder.build();
        final Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);

        if (hash == null) {
            throw new IllegalStateException("PHC is missing the password hash");
        }

        final byte[] actualBytes = new byte[hash.length];
        final List<Character> plainChars = plainTextPassword.chars().mapToObj(i -> (char)i).collect(Collectors.toList());
        final char[] plainCharArray = new char[plainChars.size()];
        for(int i = plainChars.size(); --i >= 0; plainCharArray[i] = plainChars.get(i));
        generator.generateBytes(plainCharArray, actualBytes);
        return MessageDigest.isEqual(actualBytes, hash);
    }

    protected int getAlgorithmId(CharSequence hashComponents) {
        final String id = hashComponents.toString();
        final int algorithmId = "argon2i".equalsIgnoreCase(id)
                ? Argon2Parameters.ARGON2_i
                : "argon2d".equalsIgnoreCase(id)
                ? Argon2Parameters.ARGON2_d
                : "argon2id".equalsIgnoreCase(id)
                ? Argon2Parameters.ARGON2_id
                : Integer.MIN_VALUE;
        if (algorithmId < 0) {
            throw new IllegalStateException("Unsupported algorithm: " + algorithmId);
        }
        return algorithmId;
    }

    protected int indexOfAssignmentOperator(final CharSequence sequence) {
        for (int i = sequence.length(); --i >= 0; ) {
            if (sequence.charAt(i) == '=') {
                return i;
            }
        }
        return -1;
    }

    protected CharSequence[] split(final CharSequence string) {
        final ArrayList<CharSequence> components = new ArrayList<>();
        int start = 0;
        int lastEnd = -1;
        for (int i = 0; i < string.length(); i++) {

            if (string.charAt(i) == '$') {
                if (i - start >= 0) {
                    components.add(string.subSequence(start, i));
                }
                start = i + 1;
                lastEnd = start;
            }
        }
        if(lastEnd > 0 && lastEnd < string.length()) {
            components.add(string.subSequence(lastEnd, string.length()));
        }
        return components.toArray(new CharSequence[0]);
    }

    protected CharBuffer stripPadding(final CharBuffer buffer) {
        CharBuffer result = CharBuffer.allocate(buffer.capacity());
        while(buffer.hasRemaining()) {
            final char c = buffer.get();
            if(c == '=') {
                break;
            }
            result = result.put(c);
        }

        result.limit(result.position());
        result.position(0);
        return result;
    }
}