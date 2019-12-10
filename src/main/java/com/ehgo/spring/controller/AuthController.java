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
package com.ehgo.spring.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ehgo.spring.model.AuthToken;
import com.ehgo.spring.model.Constants;
import com.ehgo.spring.model.AppResponse;
import com.ehgo.spring.model.User;
import com.ehgo.spring.model.UserDto;
import com.ehgo.spring.security.FingerprintUtil;
import com.ehgo.spring.security.JwtUtil;
import com.ehgo.spring.service.UserService;

/**
 * Rest controller action endpoints.
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(value = "/auth/")
public class AuthController {

	/**
	 * Password encoder.
	 */
    @Autowired
	private BCryptPasswordEncoder bcryptEncoder;

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

	/**
	 * Add a new member.
	 * 
	 * @param who Member data from request body.
	 * @param response Response object to place fingerprint cookie.
	 * @return Response entity with status 200 or 400.
	 */
	@PostMapping(value = "/join", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> postJoin(@RequestBody final UserDto who, final HttpServletResponse response) {
    	User user = this.userService.findOne(who.getUsername());
    	if (null != user) {
			final String message = String.format("User %s already exists", user.getUsername());
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.BAD_REQUEST);
    	}

    	final String fingerprintCookie = this.fingerprintUtil.createFingerprintCookie();
		final String fingerprintToken = this.fingerprintUtil.createFingerprintToken(fingerprintCookie);

		who.setSession(fingerprintToken);
		final List<String> roles = Collections.singletonList("ROLE_MEMBER");
    	who.setRoles(roles);
    	who.setAllowed(true);

		user = this.userService.save(who);

		final String accessToken = this.jwtUtil.generateAccessToken(user, fingerprintToken);
		final String refreshToken = this.jwtUtil.generateRefreshToken(user, fingerprintToken);
		final AuthToken token = new AuthToken(accessToken, refreshToken);

		this.fingerprintUtil.addFingerprintCookie(fingerprintCookie, response);
		final String message = String.format("Created user %s", user.getUsername());
		final AppResponse body = new AppResponse(message, token);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

	/**
	 * Log in an existing member. Use POST by convention.
	 * 
	 * @param who Member data.
	 * @param response Response object to place fingerprint cookie.
	 * @return Response entity with status 200, 401, or 403.
	 */
    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> postLogin(@RequestBody final UserDto who, final HttpServletResponse response) {
    	final User user = this.userService.findOne(who.getUsername());
    	if (null == user) {
			final String message = String.format("User %s does not exist", who.getUsername());
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.UNAUTHORIZED);
    	}
    	if (!this.bcryptEncoder.matches(who.getPassword(), user.getPassword())) {
			final String message = "Bad credentials";
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.UNAUTHORIZED);
    	}
    	if (!user.isAllowed()) {
			final String message = String.format("Account locked for %s", user.getUsername());
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.FORBIDDEN);
    	}

    	final String fingerprintCookie = this.fingerprintUtil.createFingerprintCookie();
		final String fingerprintToken = this.fingerprintUtil.createFingerprintToken(fingerprintCookie);

		who.setSession(fingerprintToken);
    	this.userService.update(who);

		final String accessToken = this.jwtUtil.generateAccessToken(user, fingerprintToken);
		final String refreshToken = this.jwtUtil.generateRefreshToken(user, fingerprintToken);
		final AuthToken token = new AuthToken(accessToken, refreshToken);

		this.fingerprintUtil.addFingerprintCookie(fingerprintCookie, response);
		final String message = String.format("Logged in as %s", user.getUsername());
		final AppResponse body = new AppResponse(message, token);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Refresh authorization token.
     * 
     * @param authToken Refresh token.
     * @param request Request with fingerprint cookie.
     * @return Response entity with status 200 or 401.
     */
    @PreAuthorize("hasRole('MEMBER') OR hasRole('ADMIN')")
    @GetMapping(value = "/refresh", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> getToken(
			@RequestAttribute(value = Constants.ATTRIBUTE_TOKEN) final String authToken,
			final HttpServletRequest request) {
        if (!this.jwtUtil.validateRefreshToken(authToken)) {
			final String message = "Not a refresh token";
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.UNAUTHORIZED);
        }

		final String fingerprintCookie = this.fingerprintUtil.getFingerprintCookie(request);
		final String fingerprintToken = this.fingerprintUtil.createFingerprintToken(fingerprintCookie);

		final String id = this.jwtUtil.getIdFromToken(authToken);
		final String username = this.jwtUtil.getUsernameFromToken(authToken);
		final List<String> roles = this.jwtUtil.getRolesFromToken(authToken);

		final User user = new User();
		user.setId(id);
		user.setUsername(username);
		user.setRoles(roles);
		user.setSession(fingerprintToken);

		final String accessToken = this.jwtUtil.generateAccessToken(user, fingerprintToken);
		final String refreshToken = this.jwtUtil.generateRefreshToken(user, fingerprintToken);

		final AuthToken token = new AuthToken(accessToken, refreshToken);
		final AppResponse body = new AppResponse(null, token);

		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Logout. Use DELETE by convention.
     * 
     * @param authToken Authorization token from request header.
     * @return Response entity with status 200 or 401.
     */
    @PreAuthorize("hasRole('MEMBER') OR hasRole('ADMIN')")
    @DeleteMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> deleteLogout(
    		@RequestAttribute(value = Constants.ATTRIBUTE_TOKEN) final String authToken) {
    	// Allow logout with access or refresh token.
    	final String username = this.jwtUtil.getUsernameFromToken(authToken);
		final UserDto who = new UserDto();
		who.setUsername(username);
		who.setSession(null);

		this.userService.update(who);

		final String message = String.format("Logged out: %s", username);
		final AppResponse body = new AppResponse(message, null);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

	/**
	 * Allow or deny member account access, or revoke JWT.
	 * 
	 * @param action Action to perform on id: allow, deny, revoke.
	 * @param id Member name.
	 * @return Response entity with status 200, 400, or 404.
	 */
    @PreAuthorize("hasRole('ADMIN')")
	@PutMapping(value = "/access/{action}/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> putAccess(@PathVariable final String action, @PathVariable final String id) {
    	Boolean allowed = "allow".equals(action) ? true : null;
    	if (null == allowed && "deny".equals(action)) {
    		allowed = false;
    	}
    	final boolean revoke = "revoke".equals(action) ? true : false;
    	if (null == allowed && !revoke) {
			final String message = String.format("Unrecognized access %s", action);
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.NOT_FOUND);
    	}
    	final User user = this.userService.findOne(id);
    	if (null == user) {
			final String message = String.format("User %s does not exist", id);
			final AppResponse body = new AppResponse(message, null);
			return new ResponseEntity<AppResponse>(body, HttpStatus.BAD_REQUEST);
    	}
    	final UserDto who = new UserDto();
    	who.setId(user.getId());
    	who.setUsername(id);
    	if (null != allowed) {
    		who.setAllowed(allowed);
    	}
    	this.userService.update(who);

    	String message = null;
    	if (revoke) {
    		message = String.format("Tokens revoked for user %s", id);
    	} else {
    		message = String.format("User %s account access set to %s", id, action);
    	}
		final AppResponse body = new AppResponse(message, null);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

}
