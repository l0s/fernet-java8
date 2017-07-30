package com.macasaet.fernet.example.autofill;

/**
 * This represents sensitive personally identifying information. The first time a customer signs up for a
 * notification, she will need to provide all of this information. This data will also be encrypted and stored for
 * subsequent requests.
 *
 * <p>Copyright &copy; 2017 Carlos Macasaet.</p>
 *
 * @author Carlos Macasaet
 */
public class Customer {

    public String firstName;
    public String lastName;
    public String emailAddress;

}