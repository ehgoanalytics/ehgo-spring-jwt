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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.ehgo.spring.model.Constants;
import com.ehgo.spring.security.FingerprintUtil;

/**
 * Unit tests for FingerprintUtil.
 */
public final class FingerprintUtilTest {

	/**
	 * FingerprintUtil to test.
	 */
	private final FingerprintUtil fpu = new FingerprintUtil();

	@Test
	void testCookieAndTokenNotEqual() {
		final String cookie = this.fpu.createFingerprintCookie();
		final String token = this.fpu.createFingerprintToken(cookie);
		assertNotEquals(cookie, token);
	}
	
	@Test
	void testVerifyCookieAndTokenEqual() {
		final String cookie = this.fpu.createFingerprintCookie();
		final String token = this.fpu.createFingerprintToken(cookie);
		assertTrue(this.fpu.verify(cookie, token));
	}

	@Test
	void testVerifyCookieAndTokenNotEqual() {
		final String cookie1 = this.fpu.createFingerprintCookie();
		final String token1 = this.fpu.createFingerprintToken(cookie1);
		final String cookie2 = this.fpu.createFingerprintCookie();
		assertFalse(this.fpu.verify(cookie2, token1));
	}

	@Test
	void testGetFingerprintCookie() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final Cookie cookie = new Cookie(Constants.FINGERPRINT_NAME, fingerprint);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		assertEquals(fingerprint, this.fpu.getFingerprintCookie(request));
	}

	@Test
	void testAddFingerprintCookie() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		this.fpu.addFingerprintCookie(fingerprint, response);
		assertNotEquals(null, response.getCookies());
	}

	@Test
	void testAddFingerprintCookieDomain() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		this.fpu.addFingerprintCookie(fingerprint, response);
		final Cookie cookie = response.getCookies()[0];
		assertEquals(Constants.FINGERPRINT_DOMAIN, cookie.getDomain());
	}

	@Test
	void testAddFingerprintCookieHttpOnly() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		this.fpu.addFingerprintCookie(fingerprint, response);
		final Cookie cookie = response.getCookies()[0];
		assertTrue(cookie.isHttpOnly());
	}

	@Test
	void testAddFingerprintCookiePath() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		this.fpu.addFingerprintCookie(fingerprint, response);
		final Cookie cookie = response.getCookies()[0];
		assertEquals(Constants.FINGERPRINT_PATH, cookie.getPath());
	}

	@Test
	void testAddFingerprintCookieSecure() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		this.fpu.addFingerprintCookie(fingerprint, response);
		final Cookie cookie = response.getCookies()[0];
		assertTrue(cookie.getSecure());
	}

	@Test
	void testAddFingerprintCookieValue() {
		final String fingerprint = this.fpu.createFingerprintCookie();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		this.fpu.addFingerprintCookie(fingerprint, response);
		final Cookie cookie = response.getCookies()[0];
		assertEquals(fingerprint, cookie.getValue());
	}

}
