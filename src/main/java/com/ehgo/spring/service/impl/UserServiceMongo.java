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
package com.ehgo.spring.service.impl;

import com.ehgo.spring.dao.UserMongo;
import com.ehgo.spring.model.Constants;
import com.ehgo.spring.model.User;
import com.ehgo.spring.model.UserDto;
import com.ehgo.spring.service.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * User details service.
 */
@Service(value = Constants.USER_DETAILS_SERVICE)
public final class UserServiceMongo implements UserDetailsService, UserService {

	/**
	 * Data access object.
	 */
	@Autowired
	private UserMongo userDao;

	/**
	 * Password encoder.
	 */
	@Autowired
	private BCryptPasswordEncoder bcryptEncoder;

	@Override
	public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
		final User user = findOne(username);
		if (null == user) {
			throw new UsernameNotFoundException(username);
		}
		final List<String> roles = user.getRoles();
		final List<SimpleGrantedAuthority> authorities = roles
				.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
	}

	@Override
    public List<User> findAll() {
		List<User> list = new ArrayList<>();
		this.userDao.findAll().iterator().forEachRemaining(list::add);
		return list;
	}

	@Override
	public void delete(final String id) {
		this.userDao.deleteById(id);
	}

	@Override
	public void delete() {
		this.userDao.deleteAll();
	}

	@Override
	public User findOne(final String username) {
		return this.userDao.findByUsername(username);
	}

	@Override
	public User findById(final String id) {
		Optional<User> optionalUser = this.userDao.findById(id);
		return optionalUser.isPresent() ? optionalUser.get() : null;
	}

    @Override
    public UserDto update(final UserDto who) {
        final User user = findOne(who.getUsername());
        if (null == user) {
        	return null;
        }
        // Update regardless of value.
    	user.setSession(who.getSession());
    	// Update allowed fields assuming valid values when not null.
    	if (null != who.getPassword()) {
    		user.setPassword(this.bcryptEncoder.encode(who.getPassword()));
    	}
    	if (null != who.getAllowed()) {
    		user.setAllowed(who.getAllowed());
    	}
    	this.userDao.save(user);
        return who;
    }

    @Override
    public User save(final UserDto who) {
	    final User user = new User();
	    user.setUsername(who.getUsername());
	    user.setPassword(this.bcryptEncoder.encode(who.getPassword()));
	    user.setRoles(who.getRoles());
	    user.setSession(who.getSession());
	    user.setAllowed(who.getAllowed());
        return this.userDao.save(user);
    }

}
