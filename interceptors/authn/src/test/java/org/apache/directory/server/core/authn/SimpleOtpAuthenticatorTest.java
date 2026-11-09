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
package org.apache.directory.server.core.authn;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;

import org.apache.directory.server.core.authn.SimpleOtpAuthenticator.TotpParameters;
import org.junit.jupiter.api.Test;


/**
 * Tests the TOTP primitives of {@link SimpleOtpAuthenticator} against the RFC 6238 appendix B vectors.
 */
public class SimpleOtpAuthenticatorTest
{
    // ASCII "12345678901234567890", "...90123456789012" and 64-byte variant, Base32 encoded
    private static final String SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String SHA256_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
    private static final String SHA512_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";


    private static String code( String uri, long seconds )
    {
        TotpParameters params = TotpParameters.parse( uri );
        assertNotNull( params );

        return SimpleOtpAuthenticator.generate( params, seconds / 30L );
    }


    @Test
    public void testRfc6238Sha1()
    {
        String uri = "otpauth://totp/x?secret=" + SHA1_SECRET + "&digits=8&algorithm=SHA1";

        assertEquals( "94287082", code( uri, 59L ) );
        assertEquals( "07081804", code( uri, 1111111109L ) );
        assertEquals( "14050471", code( uri, 1111111111L ) );
        assertEquals( "89005924", code( uri, 1234567890L ) );
        assertEquals( "69279037", code( uri, 2000000000L ) );
        assertEquals( "65353130", code( uri, 20000000000L ) );
    }


    @Test
    public void testRfc6238Sha256()
    {
        String uri = "otpauth://totp/x?secret=" + SHA256_SECRET + "&digits=8&algorithm=SHA256";

        assertEquals( "46119246", code( uri, 59L ) );
        assertEquals( "68084774", code( uri, 1111111109L ) );
    }


    @Test
    public void testRfc6238Sha512()
    {
        String uri = "otpauth://totp/x?secret=" + SHA512_SECRET + "&digits=8&algorithm=SHA512";

        assertEquals( "90693936", code( uri, 59L ) );
        assertEquals( "25091201", code( uri, 1111111109L ) );
    }


    @Test
    public void testDefaultsAndLeadingZeros()
    {
        // defaults: SHA1, 6 digits, 30s
        assertEquals( "287082", code( "otpauth://totp/Example:alice?secret=" + SHA1_SECRET + "&issuer=Example", 59L ) );
    }


    @Test
    public void testBase32()
    {
        assertArrayEquals( "foobar".getBytes( StandardCharsets.US_ASCII ),
            SimpleOtpAuthenticator.decodeBase32( "MZXW6YTBOI======" ) );
        assertArrayEquals( "foobar".getBytes( StandardCharsets.US_ASCII ),
            SimpleOtpAuthenticator.decodeBase32( "mzxw6ytboi" ) );
        assertNull( SimpleOtpAuthenticator.decodeBase32( "MZXW1" ) );
    }


    @Test
    public void testRejectedUris()
    {
        assertNull( TotpParameters.parse( null ) );
        assertNull( TotpParameters.parse( "otpauth://hotp/x?secret=" + SHA1_SECRET + "&counter=1" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x?secret=" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x?secret=!!!" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x?secret=" + SHA1_SECRET + "&algorithm=MD5" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x?secret=" + SHA1_SECRET + "&digits=4" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x?secret=" + SHA1_SECRET + "&period=0" ) );
        assertNull( TotpParameters.parse( "otpauth://totp/x?secret=" + SHA1_SECRET + "&digits=abc" ) );
    }
}