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
package com.ehgo.spring.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Member data for API related tasks.
 */
public class User {

	/**
	 * Member database id.
	 */
    private String id;

    /**
     * Member username.
     */
    private String username;

    /**
     * Member password.
     */
    @JsonIgnore
    private String password;

    /**
     * Member role authorizations.
     */
    private List<String> roles = new ArrayList<>();

	/**
	 * Current session id.
	 */
    @JsonIgnore
    private String session;

    /**
     * Flag for allowed member login.
     */
    @JsonIgnore
    private boolean allowed = false;

    /**
     * Get member database id.
     * @return Member database id.
     */
    public String getId() {
        return id;
    }

    /**
     * Set member database id.
     * @param id Member database id.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get member username.
     * @return Member username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Set member username.
     * @param username Member username.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Set member password.
     * @return Get member password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Set member password.
     * @param password Member password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Get member role authorizations.
     * @return Member role authorizations.
     */
    public List<String> getRoles() {
    	return new ArrayList<>(this.roles);
    }

    /**
     * Set member role authorizations.
     * @param roles Member role authorizations.
     */
    public void setRoles(List<String> roles) {
    	this.roles = new ArrayList<>(roles);
    }

    /**
     * Get session id. Such as a fingerprint cookie.
     * @return Session id.
     */
    public String getSession() {
    	return this.session;
    }

    /**
     * Set session id. Such as a fingerprint cookie.
     * @param session Session id.
     */
    public void setSession(final String session) {
    	this.session = session;
    }

    /**
     * Get allowed flag.
     * @return True for allowed user.
     */
    public boolean isAllowed() {
    	return this.allowed;
    }

    /**
     * Set allowed flag.
     * @param allowed User login allowed status.
     */
    public void setAllowed(final boolean allowed) {
    	this.allowed = allowed;
    }

}
