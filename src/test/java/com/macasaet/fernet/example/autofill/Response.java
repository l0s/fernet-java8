package com.macasaet.fernet.example.autofill;

import com.macasaet.fernet.Token;

/**
 * This represents the response from the API. It may be stored in insecure client storage (e.g. cookie). It allows
 * the client to present a simplified interface so that the customer does not need to re-enter sensitive
 * information. If the customer's computer is stolen or compromised, the worst that can happen is that another
 * person can register the customer for other notification types (from which the customer can unsubscribe). However,
 * the customer's personal information cannot be viewed.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Response {

    /**
     * This contains encrypted sensitive information required for subsequent registration requests. If stolen, it
     * can only be used until {@link #expirationDateTime}. This is just the serialised version of a {@link Token}.
     * It is generated server-side and can only be decrypted server-side.
     */
    public String secureEnvelope;

    /**
     * This is an ISO-8601 timestamp that tells the client when {@link #secureEnvelope} will no longer be valid.
     * After that time, the client will need to solicit the sensitive information from the customer again.
     */
    public String expirationDateTime;

}