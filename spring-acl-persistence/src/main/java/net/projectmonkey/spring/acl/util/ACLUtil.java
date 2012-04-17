package net.projectmonkey.spring.acl.util;

import java.util.List;

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;

/*
	Copyright 2012 Andy Moody
	
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
	
	    http://www.apache.org/licenses/LICENSE-2.0
	
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

/**
 * 
 * Wrapper class for {@link PermissionGrantingStrategy}
 * and {@link AclAuthorizationStrategy} allowing us to
 * have a single parameter passed around rather than multiple.
 * 
 * @author Andy Moody
 */
public class ACLUtil implements PermissionGrantingStrategy, AclAuthorizationStrategy{
	
	private final PermissionGrantingStrategy permissionGrantingStrategy;
	private final AclAuthorizationStrategy aclAuthorizationStrategy;

	public ACLUtil(final PermissionGrantingStrategy permissionGrantingStrategy,
			final AclAuthorizationStrategy aclAuthorizationStrategy) {
		this.permissionGrantingStrategy = permissionGrantingStrategy;
		this.aclAuthorizationStrategy = aclAuthorizationStrategy;
	}

	@Override
	public void securityCheck(final Acl acl, final int changeType) {
		aclAuthorizationStrategy.securityCheck(acl, changeType);
	}

	@Override
	public boolean isGranted(final Acl acl, final List<Permission> permission, final List<Sid> sids, final boolean administrativeMode) {
		return permissionGrantingStrategy.isGranted(acl, permission, sids, administrativeMode);
	}

}
