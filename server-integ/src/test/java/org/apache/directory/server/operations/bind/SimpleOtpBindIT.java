/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.server.operations.bind;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;


/**
 * Tests the simpleotp authentication choice, verified as TOTP against otpAuthUri.
 */
@ExtendWith( { ApacheDSTestExtension.class } )
@ApplyLdifs(
    {
        "dn: uid=ok,ou=users,ou=system",
        "objectClass: inetOrgPerson", "objectClass: organizationalPerson", "objectClass: person",
        "objectClass: top", "objectClass: simpleOtpUser",
        "userPassword: secret", "uid: ok", "cn: ok", "sn: ok",
        "otpAuthUri: otpauth://totp/Example:ok?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example",

        "", 
        "dn: uid=wrongotp,ou=users,ou=system",
        "objectClass: inetOrgPerson", "objectClass: organizationalPerson", "objectClass: person",
        "objectClass: top", "objectClass: simpleOtpUser",
        "userPassword: secret", "uid: wrongotp", "cn: wrongotp", "sn: wrongotp",
        "otpAuthUri: otpauth://totp/Example:w?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",

        "", 
        "dn: uid=wrongpw,ou=users,ou=system",
        "objectClass: inetOrgPerson", "objectClass: organizationalPerson", "objectClass: person",
        "objectClass: top", "objectClass: simpleOtpUser",
        "userPassword: secret", "uid: wrongpw", "cn: wrongpw", "sn: wrongpw",
        "otpAuthUri: otpauth://totp/Example:p?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",

        "", 
        "dn: uid=replay,ou=users,ou=system",
        "objectClass: inetOrgPerson", "objectClass: organizationalPerson", "objectClass: person",
        "objectClass: top", "objectClass: simpleOtpUser",
        "userPassword: secret", "uid: replay", "cn: replay", "sn: replay",
        "otpAuthUri: otpauth://totp/Example:r?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",

        "", 
        "dn: uid=nootp,ou=users,ou=system",
        "objectClass: inetOrgPerson", "objectClass: organizationalPerson", "objectClass: person",
        "objectClass: top",
        "userPassword: secret", "uid: nootp", "cn: nootp", "sn: nootp" })
@CreateDS(allowAnonAccess = true, name = "SimpleOtpBindIT-class")
@CreateLdapServer(transports =
    { @CreateTransport(protocol = "LDAP") })
public class SimpleOtpBindIT extends AbstractLdapTestUnit
{
    private static final String BASE = "ou=users,ou=system";

    /** The ASCII secret "12345678901234567890" */
    private static final byte[] SECRET = "12345678901234567890".getBytes( StandardCharsets.US_ASCII );


    /** An independent RFC 6238 SHA1/6 digits/30s implementation, offset by a number of steps */
    private static String totp( int stepOffset ) throws Exception
    {
        long step = System.currentTimeMillis() / 30000L + stepOffset;
        byte[] counter = new byte[8];

        for ( int i = 7; i >= 0; i-- )
        {
            counter[i] = ( byte ) step;
            step >>>= 8;
        }

        Mac mac = Mac.getInstance( "HmacSHA1" );
        mac.init( new SecretKeySpec( SECRET, "HmacSHA1" ) );
        byte[] h = mac.doFinal( counter );
        int o = h[h.length - 1] & 0x0F;
        int bin = ( ( h[o] & 0x7F ) << 24 ) | ( ( h[o + 1] & 0xFF ) << 16 ) | ( ( h[o + 2] & 0xFF ) << 8 )
            | ( h[o + 3] & 0xFF );

        return String.format( "%06d", bin % 1000000 );
    }


    private LdapNetworkConnection connect() throws Exception
    {
        return new LdapNetworkConnection( "localhost", getLdapServer().getPort() );
    }


    private void assertBindFails( String uid, String password, String otp ) throws Exception
    {
        try ( LdapNetworkConnection c = connect() )
        {
            BindResponse r = c.bindSimpleOtp( "uid=" + uid + "," + BASE, password, otp );
            assertEquals( ResultCodeEnum.INVALID_CREDENTIALS, r.getLdapResult().getResultCode() );
            assertFalse( c.isAuthenticated() );
        }
    }


    @Test
    public void testSuccess() throws Exception
    {
        try ( LdapNetworkConnection c = connect() )
        {
            BindResponse r = c.bindSimpleOtp( "uid=ok," + BASE, "secret", totp( 0 ) );
            assertEquals( ResultCodeEnum.SUCCESS, r.getLdapResult().getResultCode() );
            assertTrue( c.isAuthenticated() );
        }
    }


    @Test
    public void testWrongOtp() throws Exception
    {
        // Far outside the accepted drift window
        assertBindFails( "wrongotp", "secret", totp( 10 ) );
        assertBindFails( "wrongotp", "secret", "" );
    }


    @Test
    public void testWrongPassword() throws Exception
    {
        assertBindFails( "wrongpw", "bad", totp( 0 ) );
    }


    @Test
    public void testWrongPasswordDoesNotConsumeCode() throws Exception
    {
        String code = totp( 0 );

        assertBindFails( "wrongpw", "bad", code );

        try ( LdapNetworkConnection c = connect() )
        {
            c.bindSimpleOtp( "uid=wrongpw," + BASE, "secret", code );
            assertTrue( c.isAuthenticated() );
        }
    }


    @Test
    public void testReplayIsRejected() throws Exception
    {
        String code = totp( 0 );

        try ( LdapNetworkConnection c = connect() )
        {
            c.bindSimpleOtp( "uid=replay," + BASE, "secret", code );
            assertTrue( c.isAuthenticated() );
        }

        assertBindFails( "replay", "secret", code );
    }


    @Test
    public void testNoOtpAuthUriFails() throws Exception
    {
        assertBindFails( "nootp", "secret", totp( 0 ) );
    }


    @Test
    public void testPlainSimpleBindIsNotAffected() throws Exception
    {
        try ( LdapNetworkConnection c = connect() )
        {
            c.bind( "uid=ok," + BASE, "secret" );
            assertTrue( c.isAuthenticated() );
        }
    }
}