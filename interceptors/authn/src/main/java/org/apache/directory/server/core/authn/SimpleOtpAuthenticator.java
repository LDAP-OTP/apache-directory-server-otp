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


import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.authn.ppolicy.PasswordPolicyException;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;


/**
 * An {@link Authenticator} for the <code>simpleotp</code> LDAP authentication choice
 * (<code>[4] SEQUENCE { password OCTET STRING, otpvalue OCTET STRING }</code>).
 * <p>
 * The password is verified against <code>userPassword</code> exactly as the simple
 * authenticator does. The one-time password is verified as a TOTP (RFC 6238) value,
 * using the parameters of one of the entry's <code>otpAuthUri</code> values
 * (<code>otpauth://totp/LABEL?secret=BASE32[&amp;algorithm=..][&amp;digits=..][&amp;period=..]</code>).
 * Only TOTP is supported; HOTP URIs are ignored. A code is accepted once only: a code
 * for a time step not newer than the last accepted one for that DN is rejected.
 * <p>
 * Both factors are always evaluated, and every failure is reported with the same
 * message, so a client cannot tell which factor was wrong.
 */
public class SimpleOtpAuthenticator extends AbstractAuthenticator
{
    /** The attribute holding the key URI(s) */
    public static final String OTP_AUTH_URI_AT = "otpAuthUri";

    /** Number of time steps accepted before/after the current one, to tolerate clock drift */
    private static final int ALLOWED_DRIFT_STEPS = 1;

    private static final String GENERIC_FAILURE = "Invalid credentials";

    /** The last accepted time step, per normalized DN (replay protection) */
    private final Map<String, Long> lastAcceptedStep = new ConcurrentHashMap<>();


    /**
     * Creates a new instance.
     */
    public SimpleOtpAuthenticator()
    {
        super( AuthenticationLevel.SIMPLE );
    }


    /**
     * Creates a new instance.
     *
     * @param baseDn The base DN for this authenticator
     */
    public SimpleOtpAuthenticator( Dn baseDn )
    {
        super( AuthenticationLevel.SIMPLE, baseDn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapPrincipal authenticate( BindOperationContext bindContext ) throws LdapException
    {
        byte[] password = bindContext.getCredentials();
        byte[] otp = bindContext.getOtpValue();

        Entry userEntry = lookupUserEntry( bindContext );
        bindContext.setEntry( new ClonedServerEntry( userEntry ) );

        PasswordPolicyException ppe = null;

        try
        {
            checkPwdPolicy( userEntry );
        }
        catch ( PasswordPolicyException e )
        {
            ppe = e;
        }

        boolean passwordOk = checkPassword( userEntry, password );
        boolean otpOk = checkOtp( bindContext.getDn(), userEntry, otp, passwordOk );

        if ( !passwordOk || !otpOk )
        {
            LOG.info( "SimpleOTP authentication failed for {}", bindContext.getDn().getName() );
            throw new LdapAuthenticationException( GENERIC_FAILURE );
        }

        if ( ppe != null )
        {
            throw ppe;
        }

        LdapPrincipal principal = new LdapPrincipal( getDirectoryService().getSchemaManager(),
            bindContext.getDn(), AuthenticationLevel.SIMPLE );
        setAddresses( bindContext, principal );

        return principal;
    }


    private Entry lookupUserEntry( BindOperationContext bindContext ) throws LdapException
    {
        Entry userEntry = bindContext.getPrincipal();

        try
        {
            if ( userEntry == null )
            {
                LookupOperationContext lookupContext = new LookupOperationContext(
                    getDirectoryService().getAdminSession(), bindContext.getDn(),
                    SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES );

                lookupContext.setPartition( bindContext.getPartition() );
                lookupContext.setTransaction( bindContext.getTransaction() );

                userEntry = getDirectoryService().getPartitionNexus().lookup( lookupContext );
            }
        }
        catch ( Exception cause )
        {
            LdapAuthenticationException e = new LdapAuthenticationException( GENERIC_FAILURE );
            e.initCause( cause );
            throw e;
        }

        if ( userEntry == null )
        {
            throw new LdapAuthenticationException( GENERIC_FAILURE );
        }

        return userEntry;
    }


    private boolean checkPassword( Entry userEntry, byte[] password )
    {
        Attribute userPassword = userEntry.get( SchemaConstants.USER_PASSWORD_AT );
        boolean ok = false;

        if ( ( userPassword != null ) && ( password != null ) )
        {
            for ( Value value : userPassword )
            {
                if ( PasswordUtil.compareCredentials( password, value.getBytes() ) )
                {
                    ok = true;
                }
            }
        }

        return ok;
    }


    private boolean checkOtp( Dn dn, Entry userEntry, byte[] otp, boolean consume )
    {
        if ( ( otp == null ) || ( otp.length == 0 ) )
        {
            return false;
        }

        Attribute uris = userEntry.get( OTP_AUTH_URI_AT );

        if ( uris == null )
        {
            return false;
        }

        long now = getDirectoryService().getTimeProvider().currentIimeMillis();
        String key = dn.getNormName();

        for ( Value value : uris )
        {
            TotpParameters params = TotpParameters.parse( value.getString() );

            if ( params == null )
            {
                continue;
            }

            long step = matchingStep( params, otp, now );

            if ( step >= 0 )
            {
                if ( !consume )
                {
                    return false;
                }

                return acceptStep( key, step );
            }
        }

        return false;
    }


    /**
     * Atomically records the step as used. Fails if it is not newer than the last accepted one.
     */
    private boolean acceptStep( String key, long step )
    {
        boolean[] accepted = new boolean[1];

        lastAcceptedStep.compute( key, ( k, last ) ->
        {
            if ( ( last == null ) || ( step > last ) )
            {
                accepted[0] = true;
                return step;
            }

            return last;
        } );

        return accepted[0];
    }


    /**
     * @return the matching time step, or -1
     */
    private static long matchingStep( TotpParameters params, byte[] otp, long nowMillis )
    {
        long current = Math.floorDiv( nowMillis / 1000L, params.period );
        long found = -1L;

        for ( int i = -ALLOWED_DRIFT_STEPS; i <= ALLOWED_DRIFT_STEPS; i++ )
        {
            long step = current + i;

            if ( step < 0 )
            {
                continue;
            }

            byte[] expected = generate( params, step ).getBytes( StandardCharsets.UTF_8 );

            // Evaluate every candidate: no early exit on the first match
            if ( MessageDigest.isEqual( expected, otp ) && ( step > found ) )
            {
                found = step;
            }
        }

        return found;
    }


    /**
     * Computes the RFC 6238 TOTP (RFC 4226 dynamic truncation) value for a time step.
     */
    static String generate( TotpParameters params, long step )
    {
        byte[] counter = new byte[8];

        for ( int i = 7; i >= 0; i-- )
        {
            counter[i] = ( byte ) ( step & 0xFF );
            step >>>= 8;
        }

        try
        {
            Mac mac = Mac.getInstance( params.hmacName );
            mac.init( new SecretKeySpec( params.secret, params.hmacName ) );
            byte[] hash = mac.doFinal( counter );

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ( ( hash[offset] & 0x7F ) << 24 )
                | ( ( hash[offset + 1] & 0xFF ) << 16 )
                | ( ( hash[offset + 2] & 0xFF ) << 8 )
                | ( hash[offset + 3] & 0xFF );

            long mod = 1L;

            for ( int i = 0; i < params.digits; i++ )
            {
                mod *= 10L;
            }

            StringBuilder sb = new StringBuilder( Long.toString( binary % mod ) );

            while ( sb.length() < params.digits )
            {
                sb.insert( 0, '0' );
            }

            return sb.toString();
        }
        catch ( GeneralSecurityException e )
        {
            throw new IllegalStateException( "HMAC unavailable: " + params.hmacName, e );
        }
    }


    /**
     * The TOTP parameters carried by an <code>otpauth://totp/</code> key URI.
     */
    static final class TotpParameters
    {
        final byte[] secret;
        final String hmacName;
        final int digits;
        final long period;


        private TotpParameters( byte[] secret, String hmacName, int digits, long period )
        {
            this.secret = secret;
            this.hmacName = hmacName;
            this.digits = digits;
            this.period = period;
        }


        /**
         * @return the parameters, or null if the value is not a usable TOTP key URI
         */
        static TotpParameters parse( String uri )
        {
            if ( uri == null )
            {
                return null;
            }

            String prefix = "otpauth://totp/";

            if ( !uri.regionMatches( true, 0, prefix, 0, prefix.length() ) )
            {
                return null;
            }

            int q = uri.indexOf( '?' );

            if ( q < 0 )
            {
                return null;
            }

            String secretText = null;
            String algorithm = "SHA1";
            int digits = 6;
            long period = 30L;

            try
            {
                for ( String pair : uri.substring( q + 1 ).split( "&" ) )
                {
                    int eq = pair.indexOf( '=' );

                    if ( eq < 0 )
                    {
                        continue;
                    }

                    String name = pair.substring( 0, eq ).toLowerCase( Locale.ROOT );
                    String val = java.net.URLDecoder.decode( pair.substring( eq + 1 ), "UTF-8" );

                    switch ( name )
                    {
                        case "secret":
                            secretText = val;
                            break;

                        case "algorithm":
                            algorithm = val.toUpperCase( Locale.ROOT );
                            break;

                        case "digits":
                            digits = Integer.parseInt( val );
                            break;

                        case "period":
                            period = Long.parseLong( val );
                            break;

                        default:
                            break;
                    }
                }
            }
            catch ( Exception e )
            {
                return null;
            }

            String hmac;

            switch ( algorithm )
            {
                case "SHA1":
                    hmac = "HmacSHA1";
                    break;

                case "SHA256":
                    hmac = "HmacSHA256";
                    break;

                case "SHA512":
                    hmac = "HmacSHA512";
                    break;

                default:
                    return null;
            }

            if ( ( digits < 6 ) || ( digits > 8 ) || ( period < 1 ) || ( period > 3600 ) )
            {
                return null;
            }

            byte[] secret = decodeBase32( secretText );

            if ( ( secret == null ) || ( secret.length == 0 ) )
            {
                return null;
            }

            return new TotpParameters( secret, hmac, digits, period );
        }
    }


    /**
     * RFC 4648 Base32 decoding; tolerant of case, padding and spaces.
     *
     * @return the decoded bytes, or null if the input is invalid
     */
    static byte[] decodeBase32( String text )
    {
        if ( text == null )
        {
            return null;
        }

        List<Byte> out = new ArrayList<>();
        int buffer = 0;
        int bits = 0;

        for ( char c : text.toCharArray() )
        {
            if ( ( c == '=' ) || ( c == ' ' ) )
            {
                continue;
            }

            int v;

            if ( ( c >= 'A' ) && ( c <= 'Z' ) )
            {
                v = c - 'A';
            }
            else if ( ( c >= 'a' ) && ( c <= 'z' ) )
            {
                v = c - 'a';
            }
            else if ( ( c >= '2' ) && ( c <= '7' ) )
            {
                v = c - '2' + 26;
            }
            else
            {
                return null;
            }

            buffer = ( buffer << 5 ) | v;
            bits += 5;

            if ( bits >= 8 )
            {
                out.add( ( byte ) ( ( buffer >> ( bits - 8 ) ) & 0xFF ) );
                bits -= 8;
            }
        }

        byte[] result = new byte[out.size()];

        for ( int i = 0; i < result.length; i++ )
        {
            result[i] = out.get( i );
        }

        return result;
    }
}
