package org.springframework.security.acls.domain;

import java.util.List;

import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;

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
