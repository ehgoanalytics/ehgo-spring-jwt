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

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.PrematureJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ehgo.spring.model.User;
import com.ehgo.spring.service.UserService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ehgo.spring.model.AppPrincipal;
import com.ehgo.spring.model.Constants;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT authentication filter.
 */
public final class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * Client fingerprint utility.
     */
	@Autowired
	private FingerprintUtil fingerprintUtil;

	/**
	 * JWT utility.
	 */
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Member service.
     */
	@Autowired
    private UserService userService;

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		final String header = req.getHeader(Constants.AUTH_HEADER);
		if (null == header) {
			chain.doFilter(req, res);
			return;
		}
		if (!header.trim().startsWith(Constants.AUTH_PREFIX)) {
			final String message = "Missing bearer token";
			sendError(res, message, HttpStatus.BAD_REQUEST.value(), null);
			return;
		}
		// How do we know here of an encrypted bearer token?!
		final String encrypted = header.replace(Constants.AUTH_PREFIX, "").trim();
		try {
			final String authToken = this.jwtUtil.decryptToken(encrypted.trim());
	        final String username = this.jwtUtil.getUsernameFromToken(authToken);
			final String tokenSession = this.jwtUtil.getSessionFromToken(authToken);
	    	final User user = this.userService.findOne(username);
	    	final String userSession = user.getSession();
	    	// Check for prior logout.
	    	if (null == userSession) {
				final String message = "Not logged in";
				sendError(res, message, HttpStatus.UNAUTHORIZED.value(), null);
				return;
	    	}
	    	// Check for an unexpired token with a different client fingerprint (session).
	    	if (!userSession.equals(tokenSession)) {
				final String message = String.format("Invalid bearer token");
				sendError(res, message, HttpStatus.BAD_REQUEST.value(), null);
				return;
	    	}
	    	// Check for token used from different browser.
			final String fingerprintCookie = this.fingerprintUtil.getFingerprintCookie(req);
			if (!this.jwtUtil.validateToken(authToken, fingerprintCookie)) {
				final String message = "Invalid fingerprint";
				sendError(res, message, HttpStatus.UNAUTHORIZED.value(), null);
				return;
			}
			final String id = this.jwtUtil.getIdFromToken(authToken);
			final AppPrincipal principal = new AppPrincipal(username, id);
			final Object credentials = tokenSession;
			final List<SimpleGrantedAuthority> authorities = getAuthorities(authToken);
			final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
					principal, credentials, authorities);
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
			final String message = String.format("Authenticated user %s", username);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			// Some endpoints need the decrypted token.
			req.setAttribute(Constants.ATTRIBUTE_TOKEN, authToken);
			this.logger.info(message);
			chain.doFilter(req, res);
		} catch (IllegalArgumentException e) {
			final String message = "Failed to parse authorization token";
			sendError(res, message, HttpStatus.BAD_REQUEST.value(), null);
		} catch (PrematureJwtException e) {
			final String message = "Token not yet valid";
			sendError(res, message, HttpStatus.UNAUTHORIZED.value(), null);
		} catch (ExpiredJwtException e) {
			final String message = "Token expired";
			sendError(res, message, HttpStatus.UNAUTHORIZED.value(), null);
		} catch (SecurityException e) {
			final String message = "Unable to verify token signature";
			sendError(res, message, HttpStatus.BAD_REQUEST.value(), null);
		} catch (Throwable t) {
			// Hope never to get here.
			final String message = "Close your eyes and think of England";
			sendError(res, message, HttpStatus.INTERNAL_SERVER_ERROR.value(), t);
		}
	}

	/**
	 * Get list of authorities from the token.
	 * 
	 * @param token JWT.
	 * @return List of authorities.
	 */
	private List<SimpleGrantedAuthority> getAuthorities(final String token) {
		final List<String> roles = this.jwtUtil.getRolesFromToken(token);
		final List<SimpleGrantedAuthority> authorities = roles
				.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
		return authorities;
	}

	/**
	 * Send a simple JSON error message.
	 *
	 * @param response HttpServletResponse.
	 * @param message  Message to send.
	 * @param code     HTTP status code of error.
	 * @parma t        Throwable of error.
	 * @throws IOException If a problem occurs writing to the response.
	 */
	private void sendError(final HttpServletResponse response, final String message, final int code, final Throwable t)
			throws IOException {
		if (null == t) {
			this.logger.warn(message);
		} else {
			this.logger.error(t.getMessage(), t);
		}
		final String body = String.format("{\"message\": \"%s\", \"content\": null}", message);
		response.setStatus(code);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(Constants.CHARSET);
		response.getWriter().write(body);
		response.getWriter().flush();
	}

}
