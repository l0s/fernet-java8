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
package com.macasaet.fernet.example.autofill;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAmount;
import java.util.function.Function;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.macasaet.fernet.Validator;

/**
 * This class simulates the server-side logic.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Server {

    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom random = new SecureRandom();

    // this encapsulates a signing key and symmetric encryption key
    // server-side components may share this
    // it should not be shared with any client code
    private final Key key = new Key("eJEnkKigwjZDSdV0G-XCtUwyM0C0C4l2pz82CWDDzEg=");
    private final DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT;

    // this defines how long a token will be considered valid
    // this way, if a token is stolen, it will only be useful for a limited time
    private final Duration timeToLive = Duration.ofHours(24);

    // the validator implements our custom logic for deciding whether or not to accept a token (secure envelope)
    // and if so, converting the payload into a domain object
    private final Validator<Customer> validator = new Validator<Customer>() {
        public Function<byte[], Customer> getTransformer() {
            return payload -> {
                try {
                    return mapper.readValue(payload, Customer.class);
                } catch (final IOException e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            };
        }

        public TemporalAmount getTimeToLive() {
            // if the client waits too long, they will need to re-enter their information
            return timeToLive;
        }

        public Clock getClock() {
            return clock;
        }
    };

    public Server(final Clock clock) {
        this.clock = clock;
    }

    /**
     * The client will call this to register a customer for the first time (does not have a saved token) or if the saved
     * token has expired. You can imagine that this signs up the customer to receive some sort of notification.
     *
     * @param notificationType
     *            some type of notification
     * @param firstName
     *            sensitive information that the customer had to provide just before this method was called
     * @param lastName
     *            sensitive information that the customer had to provide just before this method was called
     * @param emailAddress
     *            sensitive information that the customer had to provide just before this method was called
     * @return meta data to allow the client to register the customer for another notification type without having to
     *         solicit the sensitive information again.
     * @throws JsonProcessingException
     */
    public Response register(final String notificationType, final String firstName, final String lastName,
            final String emailAddress)
        throws JsonProcessingException {
        final Customer customer = new Customer();
        customer.firstName = firstName;
        customer.lastName = lastName;
        customer.emailAddress = emailAddress;
        // Convert the object to JSON and store it in the Fernet token payload.
        // In the example, it comes out to 185 bytes but may vary depending on the length of the name and email address.
        // We could reduce this by using a binary format like Thrift or Protocol Buffers instead of JSON. Client code
        // will not be able to extract the payload so it does not need to be taken into consideration when choosing the
        // serialisation format.
        final byte[] tokenPayload = mapper.writeValueAsBytes(customer);
        final Token token = Token.generate(random, key, tokenPayload);
        final Response retval = new Response();
        retval.secureEnvelope = token.serialise();
        retval.expirationDateTime = genExpiration();
        return retval;
    }

    /**
     * The client will call this to register a customer for another notification type if and only if the client has a
     * non-expired token containing an encrypted copy of the customer's sensitive information. If the customer never
     * provided this information or if the token is expired, the client will need to solicit the information again and
     * invoke {@link #register(String, String, String, String)} instead.
     *
     * @param notificationType
     *            a subsequent notification type that the customer would like to receive
     * @param secureEnvelope
     *            an encrypted packet containing the customer's sensitive information
     * @return meta data to allow the client to register the customer for another notification type without having to
     *         solicit the sensitive information again.
     * @throws JsonProcessingException
     */
    public Response register(final String notificationType, final String secureEnvelope)
        throws JsonProcessingException {
        final Token token = Token.fromString(secureEnvelope); // throws exception if it cannot be a token
        final Customer customer = token.validateAndDecrypt(key, validator); // throws exception if the token was forged
                                                                            // or is expired
        register(notificationType, customer);
        final byte[] tokenPayload = mapper.writeValueAsBytes(customer);
        final Token updatedToken = Token.generate(random, key, tokenPayload); // extend the TTL by generating a new
                                                                              // token
        final Response retval = new Response();
        retval.secureEnvelope = updatedToken.serialise();
        retval.expirationDateTime = genExpiration(); // update the expiration date
        return retval;
    }

    protected String genExpiration() {
        return formatter.format(Instant.now(clock).plus(timeToLive).minus(Duration.ofMinutes(5)));
    }

    /**
     * This performs the actual work of subscribing a customer to a notification type.
     *
     * @param notificationType one type of notification that the customer wishes to receive
     * @param customer sensitive information needed to subscribe to a notification type
     */
    protected void register(final String notificationType, final Customer customer) {
    }

}