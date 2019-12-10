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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import com.ehgo.spring.model.AppPrincipal;
import com.ehgo.spring.model.AppResponse;
import com.ehgo.spring.model.User;
import com.ehgo.spring.model.UserDto;
import com.ehgo.spring.service.UserService;

/**
 * Rest controller for the endpoint /api.
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(value = "/api/")
public class ApiController {

    /**
     * Member service.
     */
	@Autowired
    private UserService userService;

    /**
     * Delete all users.
     * 
     * @return Response entity with status 200.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> deleteUsers() {
		this.userService.delete();
		final String message = "All users deleted";
		final AppResponse body = new AppResponse(message, null);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Get all members.
     * 
     * @return Response entity with status OK.
     */
    @PreAuthorize("hasRole('MEMBER')")
    @GetMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> getUsers() {
		final List<User> response = this.userService.findAll();
		final AppResponse body = new AppResponse(null, response);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Add member.
     * 
     * @param who Member to add from request body.
     * @return Response entity with status 405.
     */
    @PreAuthorize("hasRole('MEMBER')")
	@PostMapping(value = "/users", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> postUsers(@RequestBody final UserDto who) {
    	final String message = "Redirect to POST /join";
		final AppResponse body = new AppResponse(message, null);
		return new ResponseEntity<AppResponse>(body, HttpStatus.METHOD_NOT_ALLOWED);
    }

    /**
     * Get member with id.
     * 
     * @param id The id of the member to get.
     * @return Response entity with status 200 or 400.
     */
    @PreAuthorize("hasRole('MEMBER')")
    @GetMapping(value = "/users/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> getUsersId(@PathVariable final String id) {
    	final User user = this.userService.findById(id);
    	if (null == user) {
        	final String message = "Bad member id";
    		final AppResponse body = new AppResponse(message, null);
    		return new ResponseEntity<AppResponse>(body, HttpStatus.BAD_REQUEST);
    	}
		final AppResponse body = new AppResponse(null, user);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Update member with id.
     * 
     * @param who Member data to update from request body.
     * @param id The id of member to update.
     * @return Response entity with status 200, 400, or 403.
     */
    @PreAuthorize("hasRole('MEMBER')")
    @PutMapping(value = "/users/{id}", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> putUsersId(@RequestBody final UserDto who, @PathVariable final String id) {
    	final AppPrincipal principal = getPrincipal();
    	if (null == principal) {
    		// Should not get here.
    		final String message = "Missing or unrecognized principal";
    		final AppResponse body = new AppResponse(message, null);
    		return new ResponseEntity<AppResponse>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    	}
    	// Check that authenticated user updates self only.
    	final ResponseEntity<AppResponse> reject = rejectRequest(principal, id, who);
    	if (null != reject) {
    		return reject;
    	}
    	final String credentials = getCredentials();
    	who.setSession(credentials);
    	who.setId(id);

    	final UserDto updated = this.userService.update(who);
    	final String message = "Update successful";
		final AppResponse body = new AppResponse(message, updated);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Delete member with id.
     * 
     * @param id The id of member to delete.
     * @return Response entity with status 200, 400, or 403.
     */
    @PreAuthorize("hasRole('MEMBER')")
    @DeleteMapping(value = "/users/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AppResponse> deleteUsersId(@PathVariable final String id) {
    	final AppPrincipal principal = getPrincipal();
    	if (null == principal) {
    		// Should not get here.
    		final String message = "Missing or unrecognized principal";
    		final AppResponse body = new AppResponse(message, null);
    		return new ResponseEntity<AppResponse>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    	}
    	// Check that authenticated user deletes self only.
    	final ResponseEntity<AppResponse> reject = rejectRequest(principal, id, null);
    	if (null != reject) {
    		return reject;
    	}
    	this.userService.delete(id);
    	final String message = "Member logged out and deleted";
		final AppResponse body = new AppResponse(message, null);
		return new ResponseEntity<AppResponse>(body, HttpStatus.OK);
    }

    /**
     * Get the principal from the security context authentication.
     * 
     * @return Principal or null.
     */
    private AppPrincipal getPrincipal() {
    	final Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    	if (null == principal || !AppPrincipal.class.isAssignableFrom(principal.getClass())) {
    		return null;
    	}
    	return ((AppPrincipal)principal);
    }

    /**
     * Get the credentials from the security context authentication.
     *
     * @return Credentials or null.
     */
    private String getCredentials() {
    	final Object credentials = SecurityContextHolder.getContext().getAuthentication().getCredentials();
    	return null == credentials ? null : credentials.toString();
    }

    /**
     * Reject requests on non-matching id.
     * 
     * @param principal Request principal.
     * @param id Request id.
     * @param who Member data from request body.
     * @return Null to accept or response entity to send as rejection.
     */
    private ResponseEntity<AppResponse> rejectRequest(final AppPrincipal principal, final String id, final UserDto who) {
    	if (!principal.getId().equals(id)) {
        	final String message = "Operation not permitted on other members";
        	final AppResponse body = new AppResponse(message, null);
        	return new ResponseEntity<AppResponse>(body, HttpStatus.FORBIDDEN);
    	}
    	if (null != who) {
	    	final String whoId = who.getId();
	    	if (null != whoId && !id.equals(whoId)) {
	        	final String message = "Different request id and member id";
	    		final AppResponse body = new AppResponse(message, null);
	    		return new ResponseEntity<AppResponse>(body, HttpStatus.BAD_REQUEST);
	    	}
    	}
    	return null;
    }

}
