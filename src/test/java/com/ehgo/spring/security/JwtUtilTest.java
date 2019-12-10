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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.ehgo.spring.model.User;

import io.jsonwebtoken.ExpiredJwtException;

/**
 * Unit tests for JwtUtil.
 */
public final class JwtUtilTest {

	/**
	 * JwtUtil to test.
	 */
	private JwtUtil jwtu = new JwtUtil();

	/**
	 * Default user.
	 */
	private final User user = new User();

	/**
	 * Default fingerprint cookie value.
	 */
	private final String fingerprintCookie;

	/**
	 * Default fingerprint token value.
	 */
	private final String fingerprintToken;

	/**
	 * A valid but expired access token.
	 */
	private static final String ACCESS_TOKEN_EXPIRED = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlcm5hbWUiLCJhdXRob3JpemF0aW9ucyI6WyJST0xFX01FTUJFUiJdLCJmaW5nZXJwcmludCI6ImJ0YVIvVHoyS2IySWZWSHliL0JNSnFGN1h1SkdoTU44OGU2aXJ1T3liY3M9IiwianRpIjoidGVzdElkIiwiaXNzIjoiaHR0cDovL2VoZ29hbmFseXRpY3MuY29tIiwiaWF0IjoxNTc1NDAzNzQwLCJuYmYiOjE1NzU0MDM3NDAsImV4cCI6MTU3NTQwNDA0MH0.u6COLdlp58wLPfILBbLkIso3eSBVH4smn8ACVUikiog";

	/**
	 * A valid but expired refresh token.
	 */
	private static final String REFRESH_TOKEN_EXPIRED = "eyJyZWZyZXNoIjp0cnVlLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlcm5hbWUiLCJhdXRob3JpemF0aW9ucyI6WyJST0xFX01FTUJFUiJdLCJmaW5nZXJwcmludCI6IlVsd3h5eEFKOXQrL3hwME9MdGpuSkRSbkdjd25pZ3VMV0x3T1A4WVBPM2s9IiwianRpIjoidGVzdElkIiwiaXNzIjoiaHR0cDovL2VoZ29hbmFseXRpY3MuY29tIiwiaWF0IjoxNTc1NDA0MDc5LCJuYmYiOjE1NzU0MDQwNzksImV4cCI6MTU3NTQwNzY3OX0.B5Q6_m7Wo9TYp-gORgSvpN5yqDkkxpUL6GfRzlk-0gc";

	/**
	 * JWT encrypted with different password.
	 */
	private static final String JWT_DIFFERENT_PASSWORD = "87nmnkjvd8h5+ROIChpwzAd2+QmSnUdK/LAZ0P+UKcbgZ9K3xeym877lJsUHlzBRY+YXqpAINF4fs7t3iEtC8JDxkSp/oM+ugvNL0mInPRbui3UiR1cMa18QhGTOovJBOyu6pYCXQ5CrUFjWI+AK3PZKuC8PG8ZJpUZyWxZQAKZoGjxsstsU/JPCTrA2wx327q+MKW+mgScGO9fhGSoD/w/rw3ExZsiiO2l7DHuCx4d8f5MYVgaYdNb9g75d75g5nRJtvJzjbRWd/LivmD65PtZeY/vkhBvWqp9uE5FTed9AJolA33OBaGhS+nJwTOJVenTasEd7qVtCAag/M9KdfuHO3n97GvyT6/a0Yzcj8uUwRw+6BXNe9XuNpIhfJ54OAFMdzx/sr6huqj9pzqVTOK7o3t+lN7jrAjhJZ0e21e00/HZLhecg0UXIkA7Zd8a9fSMCzG1aeKqH+fD2";

	public JwtUtilTest() {
		if (null == this.jwtu) {
			this.jwtu = new JwtUtil();
		}
		final FingerprintUtil fpu = new FingerprintUtil(); 
		this.fingerprintCookie = fpu.createFingerprintCookie();
		this.fingerprintToken = fpu.createFingerprintToken(this.fingerprintCookie);

		this.user.setUsername("testUsername");
		this.user.setId("testId");
		this.user.setRoles(Collections.singletonList("ROLE_MEMBER"));
		this.user.setSession(this.fingerprintToken);
	}

	@Test
	void testDecryptToken() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		boolean success = false;
		try {
			this.jwtu.decryptToken(encryptedToken);
			success = true;
		} catch (IllegalArgumentException uee) {
		}
		assertTrue(success);
    }
	
	@Test
	void testGenerateAccessTokenValid() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final Boolean valid = this.jwtu.validateToken(token, this.fingerprintCookie);
		assertTrue(valid);
	}

	@Test
	void testGenerateRefreshTokenValid() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final Boolean valid = this.jwtu.validateToken(token, this.fingerprintCookie);
		assertTrue(valid);
	}

	@Test
	void testValidateRefreshTokenTrue() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final Boolean refresh = this.jwtu.validateRefreshToken(token);
		assertTrue(refresh);
	}

	@Test
	void testValidateRefreshTokenFalse() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final Boolean refresh = this.jwtu.validateRefreshToken(token);
		assertTrue(!refresh);
	}

	@Test
	void testGetUsernameFromAccessToken() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String username = this.jwtu.getUsernameFromToken(token);
		assertEquals(this.user.getUsername(), username);
	}

	@Test
	void testGetIdFromAccessToken() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String id = this.jwtu.getIdFromToken(token);
		assertEquals(this.user.getId(), id);
	}

	@Test
	void testGetSessionFromAccessToken() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String session = this.jwtu.getSessionFromToken(token);
		assertEquals(this.user.getSession(), session);
	}

	@Test
	void testGetRolesFromAccessTokenNotNull() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final List<String> roles = this.jwtu.getRolesFromToken(token);
		assertNotEquals(null, roles);
	}

	@Test
	void testGetRolesFromAccessTokenOneRole() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final List<String> roles = this.jwtu.getRolesFromToken(token);
		assertEquals(1, roles.size());
	}

	@Test
	void testGetRolesFromAccessTokenMember() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final List<String> roles = this.jwtu.getRolesFromToken(token);
		assertEquals(user.getRoles().get(0), roles.get(0));
	}

	@Test
	void testGetUsernameFromRefreshToken() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String username = this.jwtu.getUsernameFromToken(token);
		assertEquals(this.user.getUsername(), username);
	}

	@Test
	void testGetIdFromRefreshToken() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String id = this.jwtu.getIdFromToken(token);
		assertEquals(this.user.getId(), id);
	}

	@Test
	void testGetSessionFromRefreshToken() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String session = this.jwtu.getSessionFromToken(token);
		assertEquals(this.user.getSession(), session);
	}

	@Test
	void testGetRolesFromRefreshTokenNotNull() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final List<String> roles = this.jwtu.getRolesFromToken(token);
		assertNotEquals(null, roles);
	}

	@Test
	void testGetRolesFromRefreshTokenOneRole() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final List<String> roles = this.jwtu.getRolesFromToken(token);
		assertEquals(1, roles.size());
	}

	@Test
	void testGetRolesFromRefreshTokenMember() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final List<String> roles = this.jwtu.getRolesFromToken(token);
		assertEquals(user.getRoles().get(0), roles.get(0));
	}

	@Test
	void testDecryptAccessTokenIllegalArgumentException() {
		final Exception exception = assertThrows(IllegalArgumentException.class, () -> {
			final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
			final String token = encryptedToken.substring(0, encryptedToken.length() - 3) + "bad";
			this.jwtu.decryptToken(token);
		});
		assertEquals("Unable to decrypt token: java.lang.IllegalStateException", exception.getMessage());
    }
	
	@Disabled
	@Test
	void testValidateTokenPrematureJwtException() {
		// Should not throw this exception.
		assertTrue(false);
	}

	@Test
	void testValidateTokenExpiredJwtException() {
		assertThrows(ExpiredJwtException.class, () -> {
			this.jwtu.validateToken(ACCESS_TOKEN_EXPIRED, this.fingerprintCookie);
		});
	}

	@Test
	void testValidateTokenIllegalArgumentException() {
		final String encryptedToken = this.jwtu.generateAccessToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String tokenIllegal = token.substring(3) + "bad";
		assertThrows(IllegalArgumentException.class, () -> {
			this.jwtu.validateToken(tokenIllegal, this.fingerprintCookie);
		});
	}

	@Disabled
	@Test
	void testValidateRefreshTokenPrematureJwtException() {
		// TODO: Change expiration in JwtUtil.generateRefreshToken.
		assertTrue(false);
	}

	@Test
	void testValidateRefreshTokenExpiredJwtException() {
		assertThrows(ExpiredJwtException.class, () -> {
			this.jwtu.validateToken(REFRESH_TOKEN_EXPIRED, this.fingerprintCookie);
		});
	}

	@Test
	void testValidateRefreshTokenIllegalArgumentException() {
		final String encryptedToken = this.jwtu.generateRefreshToken(this.user, this.fingerprintToken);
		final String token = decryptTokenGood(encryptedToken);
		final String tokenIllegal = token.substring(3) + "bad";
		assertThrows(IllegalArgumentException.class, () -> {
			this.jwtu.validateRefreshToken(tokenIllegal);
		});
	}

	@Test
	void testDecryptTokenDifferentPassword() {
		final Exception exception = assertThrows(IllegalArgumentException.class, () -> {
			this.jwtu.decryptToken(JWT_DIFFERENT_PASSWORD);
		});
		assertEquals("Unable to decrypt token: java.lang.IllegalStateException", exception.getMessage());
	}

	/**
	 * Decrypt a correctly encrypted token.
	 * 
	 * @param encryptedToken Correctly encrypted token.
	 * @return Decrypted token.
	 */
	private String decryptTokenGood(final String encryptedToken) {
		String token = null;
		try {
			token = this.jwtu.decryptToken(encryptedToken);
		} catch (IllegalArgumentException uee) {
			// Should not happen in unit tests.
		}
		return token;
	}

}
