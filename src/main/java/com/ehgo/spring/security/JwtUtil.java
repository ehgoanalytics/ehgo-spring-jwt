/*
Copyright (c) 2019 EHGO Analytics LLC

Redistribution and use in source and binary forms, with or
without modification, are permitted provided that the following
conditions are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided
with the distribution.

Subject to the terms and conditions of this license, each
copyright holder and contributor hereby grants to those receiving
rights under this license a perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable (except for failure to
satisfy the conditions of this license) patent license to make,
have made, use, offer to sell, sell, import, and otherwise
transfer this software, where such license applies only to those
patent claims, already acquired or hereafter acquired, licensable
by such copyright holder or contributor that are necessarily
infringed by:

(a) their Contribution(s) (the licensed copyrights of copyright
holders and non-copyrightable additions of contributors, in
source or binary form alone); or
(b) combination of their Contribution(s) with the work of
authorship to which such Contribution(s) was added by such
copyright holder or contributor, if, at the time the Contribution
is added, such addition causes such combination to be necessarily
infringed. The patent license shall not apply to any other
combinations which include the Contribution.  Except as expressly
stated above, no rights or licenses from any copyright holder or
contributor is granted under this license, whether expressly, by
implication, estoppel or otherwise.

DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
 */
package com.ehgo.spring.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.PrematureJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.bouncycastle.util.encoders.Hex;
import org.springframework.security.crypto.encrypt.BouncyCastleAesGcmBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import com.ehgo.spring.model.Constants;
import com.ehgo.spring.model.User;

import static com.ehgo.spring.model.Constants.ACCESS_TOKEN_VALIDITY_MINUTES;
import static com.ehgo.spring.model.Constants.REFRESH_TOKEN_VALIDITY_MINUTES;
import static com.ehgo.spring.model.Constants.SIGNING_KEY_PHRASE;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Manage all things related to JWT.
 */
@Component
public final class JwtUtil {

	/**
	 * Password for token encryption.
	 */
	private String password = Constants.ENCRYPTION_PASSWORD;

	/**
	 * Salt for token encryption.
	 */
	private String salt = Constants.ENCRYPTION_SALT;

	/**
	 * Token encryptor.
	 */
	private final BytesEncryptor crypt;

	/**
	 * Token signing key.
	 */
	private final Key signingKey;

    /**
     * Client fingerprint utility.
     */
	private final FingerprintUtil fingerprintUtil;

	/**
	 * Constructor. Instantiates signingKey and crypt.
	 */
	public JwtUtil() {
		this.signingKey = Keys.hmacShaKeyFor(SIGNING_KEY_PHRASE.getBytes());
		this.crypt = new BouncyCastleAesGcmBytesEncryptor(this.password, toHex(this.salt));
		this.fingerprintUtil = new FingerprintUtil();
	}

	/**
	 * Decrypt an encrypted JWT token.
	 * 
	 * @param token String to decrypt as base64.
	 * @return Decrypted JWT.
	 * @throws IllegalArgumentException If token not properly encoded.
	 */
	public String decryptToken(final String token) throws IllegalArgumentException {
		String decrypted = null;
		try {
			byte[] bytes = Base64Utils.decodeFromString(token);
			bytes = this.crypt.decrypt(bytes);
			decrypted = new String(bytes, Constants.CHARSET);
		} catch (UnsupportedEncodingException uee) {
			// Will not happen.
		} catch (RuntimeException rte) {
			final String message = String.format("Unable to decrypt token: %s", rte.getClass().getName());
			throw new IllegalArgumentException(message);
		}
		return decrypted;
	}

	/**
	 * Encrypt a JWT.
	 * 
	 * @param token JWT to encrypt.
	 * @return Encrypted JWT as base64.
	 */
	public String encryptToken(final String token) {
		String encrypted = null;
		try {
			byte[] bytes = this.crypt.encrypt(token.getBytes(Constants.CHARSET));
			encrypted = Base64Utils.encodeToString(bytes);
		} catch (UnsupportedEncodingException e) {
			// Will not happen.
		}
		return encrypted;
	}

	/**
	 * Get username from JWT subject.
	 * 
	 * @param token JWT.
	 * @return Username.
	 */
    public String getUsernameFromToken(final String token) {
		return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Get id from JWT id.
     * 
     * @param token JWT.
     * @return Id.
     */
    public String getIdFromToken(final String token) {
		return getClaimFromToken(token, Claims::getId);
    }

    /**
     * Get session from JWT session.
     *
     * @param token JWT.
     * @return Session.
     */
    public String getSessionFromToken(final String token) {
		final Claims bodyClaims = getBodyClaimsFromToken(token);
		return bodyClaims.get(Constants.FINGERPRINT_CLAIM).toString();
    }

    /**
     * Get roles from JWT.
     * 
     * @param token JWT.
     * @return List of roles.
     */
    public List<String> getRolesFromToken(final String token) {
		final Claims claims = getBodyClaimsFromToken(token);
		final Object roles = claims.get(Constants.ROLES_CLAIM);
		if (null != roles && List.class.isAssignableFrom(roles.getClass())) {
			return ((List<?>)roles).stream().map(r -> r.toString()).collect(Collectors.toList());
		}
		return new ArrayList<>();
    }

    /**
     * Create a JWT access token.
     * 
     * @param user Member data.
     * @param fingerprint Client fingerprint.
     * @return JWT.
     */
    public String generateAccessToken(final User user, final String fingerprint) {
		final Calendar c = Calendar.getInstance();
		final Date now = c.getTime();
		c.add(Calendar.MINUTE, ACCESS_TOKEN_VALIDITY_MINUTES);
		final Date expiration = c.getTime();
		final Claims claims = Jwts.claims().setSubject(user.getUsername());
		claims.put(Constants.ROLES_CLAIM, user.getRoles());
		claims.put(Constants.FINGERPRINT_CLAIM, fingerprint);
		final String token = Jwts.builder()
				.setClaims(claims)
				.setId(user.getId())
				.setIssuer(Constants.TOKEN_ISSUER)
				.setIssuedAt(now)
				.setNotBefore(now)
				.setExpiration(expiration)
				.signWith(this.signingKey, SignatureAlgorithm.HS256)
				.compact();
		return encryptToken(token);
    }

    /**
     * Create a JWT access token.
     * 
     * @param user Member data.
     * @param fingerprint Client fingerprint.
     * @return JWT.
     */
    public String generateRefreshToken(final User user, final String fingerprint) {
		final Calendar c = Calendar.getInstance();
		final Date now = c.getTime();
		c.add(Calendar.MINUTE, ACCESS_TOKEN_VALIDITY_MINUTES);
		final Date accessExpiration = c.getTime();
		c.add(Calendar.MINUTE, REFRESH_TOKEN_VALIDITY_MINUTES - ACCESS_TOKEN_VALIDITY_MINUTES);
		final Date expiration = c.getTime();
		final Map<String, Object> headerClaims = new HashMap<>();
		headerClaims.put(Constants.REFRESH_CLAIM, true);
		final Claims claims = Jwts.claims()
				.setSubject(user.getUsername());
		claims.put(Constants.ROLES_CLAIM, user.getRoles());
		claims.put(Constants.FINGERPRINT_CLAIM, fingerprint);
		final String token = Jwts.builder()
				.setHeader(headerClaims)
				.setClaims(claims)
				.setId(user.getId())
				.setIssuer(Constants.TOKEN_ISSUER)
				.setIssuedAt(now)
				// TODO: Uncommented for production.
				.setNotBefore(now) //accessExpiration)
				.setExpiration(expiration)
				.signWith(this.signingKey, SignatureAlgorithm.HS256)
				.compact();
		return encryptToken(token);
    }

    /**
     * Validate JWT.
     * 
     * @param token JWT.
     * @param fingerprintCookie Client fingerprint.
     * @return True for a valid JWT.
	 * @throws PrematureJwtException Token not yet valid.
	 * @throws ExpiredJwtException Token expired.
	 * @throws IllegalArgumentException Not a JWT.
     */
    public Boolean validateToken(final String token, final String fingerprintCookie)
    	throws PrematureJwtException, ExpiredJwtException, IllegalArgumentException {
    	try {
	    	if (null == fingerprintCookie) {
	    		return false;
	    	}
	    	final Jws<Claims> allClaims = Jwts.parser()
	                .setSigningKey(this.signingKey)
	                .parseClaimsJws(token);
	        // Necessary to check algorithm? Only if alg = none indicates okay.
	        final String algorithm = allClaims.getHeader().getAlgorithm();
	        if (!SignatureAlgorithm.HS256.name().equals(algorithm)) {
	        	return false;
	        }
	        final Object fingerprintToken = allClaims.getBody().get(Constants.FINGERPRINT_CLAIM);
	        if (null == fingerprintToken) {
	        	return false;
	        }
	        return this.fingerprintUtil.verify(fingerprintCookie, fingerprintToken.toString());
    	} catch (PrematureJwtException | ExpiredJwtException e) {
    		throw e;
    	} catch (RuntimeException rte) {
    		throw new IllegalArgumentException(rte.getMessage());
    	}
    }

	/**
	 * Validate a refresh token.
	 * 
	 * @param token Refresh token.
	 * @return True for a valid refresh token.
	 * @throws PrematureJwtException Token not yet valid.
	 * @throws ExpiredJwtException Token expired.
	 * @throws IllegalArgumentException Not a JWT.
	 */
	public Boolean validateRefreshToken(final String token)
			throws PrematureJwtException, ExpiredJwtException, IllegalArgumentException {
		Object refresh = null;
		try {
			refresh = Jwts.parser()
                .setSigningKey(this.signingKey)
                .parseClaimsJws(token).getHeader().get(Constants.REFRESH_CLAIM);
    	} catch (PrematureJwtException | ExpiredJwtException e) {
    		throw e;
    	} catch (RuntimeException rte) {
    		throw new IllegalArgumentException(rte.getMessage());
    	}
        return null != refresh;
    }

    /**
     * Get the body claims from the token.
     * 
     * @param token JWT.
     * @return Body claims.
	 * @throws PrematureJwtException Token not yet valid.
	 * @throws ExpiredJwtException Token expired.
	 * @throws IllegalArgumentException Not a JWT.
     */
    private Claims getBodyClaimsFromToken(final String token)
    	throws PrematureJwtException, ExpiredJwtException, IllegalArgumentException {
    	Jws<Claims> allClaims = null;
    	try {
    		allClaims = Jwts.parser()
    				.setSigningKey(this.signingKey)
    				.parseClaimsJws(token);
    	} catch (PrematureJwtException | ExpiredJwtException e) {
    		throw e;
    	} catch (RuntimeException rte) {
    		throw new IllegalArgumentException(rte.getMessage());
    	}
    	return allClaims.getBody();
    }

    /**
     * Get claim from JWT.
     * 
     * @param token JWT.
     * @param method Method to call on body claim object.
     * @return Claim returned from method.
     */
    private <T> T getClaimFromToken(final String token, final Function<Claims, T> method) {
    	final Claims claims = getBodyClaimsFromToken(token);
    	return method.apply(claims);
    }

	/**
	 * Convert text to hex.
	 * 
	 * @param text Text.
	 * @return Text as hex.
	 */
	private String toHex(final String text) {
		String hex = null;
		try {
			final byte[] bytes = Hex.encode(text.getBytes(Constants.CHARSET));
			hex = new String(bytes, Constants.CHARSET);
			//hex = String.format("%x", new BigInteger(1, text.getBytes(Constants.CHARSET)));
		} catch (UnsupportedEncodingException e) {
			// Will not happen.
		}
		return hex;
	}

}
