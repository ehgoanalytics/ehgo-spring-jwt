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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import com.ehgo.spring.model.Constants;

/**
 * Manage all things related to JWT client fingerprint.
 */
@Component
public final class FingerprintUtil {

	/**
	 * Create fingerprint cookie value.
	 * 
	 * @return Fingerprint cookie value.
	 */
	public String createFingerprintCookie() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Create a fingerprint to place in a JWT from a fingerprint cookie.
	 * 
	 * @param fingerprintCookie Fingerprint value.
	 * @return Fingerprint for use in a JWT.
	 */
	public String createFingerprintToken(final String fingerprintCookie) {
		String fingerprintToken = null;
		try {
			final MessageDigest digest = MessageDigest.getInstance(Constants.FINGERPRINT_ALGORITHM);
			final byte[] hash = digest.digest(fingerprintCookie.getBytes(Constants.CHARSET));
			fingerprintToken = Base64Utils.encodeToString(hash);
		} catch(NoSuchAlgorithmException | UnsupportedEncodingException ex) {
			// Won't happen.
		}
		return fingerprintToken;
	}

	/**
	 * Add a fingerprint cookie to the HTTP response.
	 * 
	 * @param fingerprint Fingerprint cookie value.
	 * @param response Response to receive the cookie.
	 */
	public void addFingerprintCookie(final String fingerprint, final HttpServletResponse response) {
		// Postman 7.11.0 does not support SameSite or cookie prefixes __Secure-Stuff
		final Cookie cookie = new Cookie(Constants.FINGERPRINT_NAME, fingerprint);
	    cookie.setSecure(true);
	    cookie.setHttpOnly(true);
	    cookie.setPath(Constants.FINGERPRINT_PATH);
	    cookie.setDomain(Constants.FINGERPRINT_DOMAIN);
	    response.addCookie(cookie);
	}

	/**
	 * Get the fingerprint cookie value from the HTTP request.
	 * 
	 * @param request HTTP request.
	 * @return Fingerprint cookie value or null.
	 */
	public String getFingerprintCookie(final HttpServletRequest request) {
		final Cookie[] cookies = request.getCookies();
		if (null == cookies || 0 == cookies.length) {
			return null;
		}
		final List<Cookie> list = Arrays.stream(cookies).collect(Collectors.toList());
		final Optional<Cookie> cookie = list.stream().filter(c -> Constants.FINGERPRINT_NAME.equals(c.getName())).findFirst();
		return cookie.isPresent() ? cookie.get().getValue() : null;
	}

	/**
	 * Verify the fingerprint cookie and fingerprint token equal each other.
	 * 
	 * @param fingerprintCookie Fingerprint cookie value.
	 * @param fingerprintToken Fingerprint token value.
	 * @return True on equality.
	 */
	public Boolean verify(final String fingerprintCookie, final String fingerprintToken) {
        final String fingerprintCookieHash = createFingerprintToken(fingerprintCookie);
        return fingerprintCookieHash.equals(fingerprintToken);
	}

}
