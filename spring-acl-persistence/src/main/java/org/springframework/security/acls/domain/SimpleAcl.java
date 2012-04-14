package org.springframework.security.acls.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.UnloadedSidException;
import org.springframework.util.Assert;

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
 * Base implementation of a MutableACL from which 
 * our custom acls can inherit.
 * This class provides some default behaviour, a lot of which
 * is taken directly from {@link AclImpl}
 * 
 * This class has to reside in the spring package so that it
 * can access methods on the {@link AccessControlEntryImpl} class.
 * 
 * @author Andy Moody
 */
@SuppressWarnings("serial")
public class SimpleAcl implements MutableAcl{
		
	private Sid owner;
	private final List<AccessControlEntry> entries;
	private final ObjectIdentity identity;
	private final List<Sid> loadedSids; // includes all requested SIDs, even if there was no ACE for a SID
	private final transient ACLUtil util;

	
	public SimpleAcl(final ObjectIdentity identity, final Sid owner, final List<AccessControlEntry> entries, final List<Sid> loadedSids, final ACLUtil util) {
		this.owner = owner;
		this.entries = entries;
		this.identity = identity;
		this.loadedSids = loadedSids;
		this.util = util;
	}
	
	
	/* Methods inherited from Acl */
	@Override
	public List<AccessControlEntry> getEntries() {
		return new ArrayList<AccessControlEntry>(entries);
	}

	@Override
	public ObjectIdentity getObjectIdentity() {
		return identity;
	}

	@Override
	public Sid getOwner() {
		return owner;
	}
	

	@Override
	public Acl getParentAcl() {
		return null;
	}

	@Override
	public boolean isEntriesInheriting() {
		return false;
	}

	@Override
	public boolean isGranted(final List<Permission> permission, final List<Sid> sids, final boolean administrativeMode)
			throws NotFoundException, UnloadedSidException {
		Assert.notEmpty(permission, "Permissions required");
        Assert.notEmpty(sids, "SIDs required");

        if (!this.isSidLoaded(sids)) {
            throw new UnloadedSidException("ACL was not loaded for one or more SID");
        }

        return util.isGranted(this, permission, sids, administrativeMode);
	}

	@Override
	public boolean isSidLoaded(final List<Sid> sids) {
		// If loadedSides is null, this indicates all SIDs were loaded
        // Also return true if the caller didn't specify a SID to find
        if ((this.loadedSids == null) || (sids == null) || (sids.size() == 0)) {
            return true;
        }

        // This ACL applies to a SID subset only. Iterate to check it applies.
        for (Sid sid: sids) {
            if (!loadedSids.contains(sid)) {
                return false;
            }
        }
        
        return true;
	}
	
	
	/* Methods inherited from MutableAcl */
	
	@Override
    public void updateAce(final int aceIndex, final Permission permission)
        throws NotFoundException {
        util.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        verifyAceIndexExists(aceIndex);

        synchronized (entries) {
            AccessControlEntryImpl ace = (AccessControlEntryImpl) entries.get(aceIndex);
            ace.setPermission(permission);
        }
    }
    
	@Override
	public void deleteAce(final int aceIndex) throws NotFoundException {
		util.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
        verifyAceIndexExists(aceIndex);

        synchronized (entries) {
            this.entries.remove(aceIndex);
        }
	}

	@Override
	public Serializable getId() {
		return identity.getIdentifier();
	}

	@Override
	public void insertAce(final int atIndexLocation, final Permission permission, final Sid sid, final boolean granting) throws NotFoundException {
		insertAce(null, atIndexLocation, permission, sid, granting);
	}

	public void insertAce(final UUID id, final int atIndexLocation, final Permission permission, final Sid sid, final boolean granting) throws NotFoundException {
		Assert.notNull(permission, "Permission required");
		Assert.notNull(sid, "Sid required");
		util.securityCheck(this, AclAuthorizationStrategy.CHANGE_GENERAL);
		if (atIndexLocation < 0) {
			throw new NotFoundException("atIndexLocation must be greater than or equal to zero");
		}
		if (atIndexLocation > this.entries.size()) {
			throw new NotFoundException("atIndexLocation must be less than or equal to the size of the AccessControlEntry collection");
		}
		AccessControlEntryImpl ace = new AccessControlEntryImpl(id, this, sid, permission, granting, false, false);
		
		synchronized (entries) {
			this.entries.add(atIndexLocation, ace);
		}
	}

	@Override
	public void setOwner(final Sid owner) {
		this.owner = owner;
	}

	@Override
	public void setEntriesInheriting(final boolean entriesInheriting) {
		throw new UnsupportedOperationException("inheritance is not currently supported");
	}

	@Override
	public void setParent(final Acl newParent) {
		throw new UnsupportedOperationException("inheritance is not currently supported");
	}

	
	/* Other methods */

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((entries == null) ? 0 : entries.hashCode());
		result = prime * result + ((identity == null) ? 0 : identity.hashCode());
		result = prime * result + ((loadedSids == null) ? 0 : loadedSids.hashCode());
		result = prime * result + ((owner == null) ? 0 : owner.hashCode());
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SimpleAcl other = (SimpleAcl) obj;
		if (entries == null)
		{
			if (other.entries != null)
				return false;
		}
		else if (!entries.equals(other.entries))
			return false;
		if (identity == null)
		{
			if (other.identity != null)
				return false;
		}
		else if (!identity.equals(other.identity))
			return false;
		if (loadedSids == null)
		{
			if (other.loadedSids != null)
				return false;
		}
		else if (!loadedSids.equals(other.loadedSids))
			return false;
		if (owner == null)
		{
			if (other.owner != null)
				return false;
		}
		else if (!owner.equals(other.owner))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SimpleAcl [owner=" + owner + ", entries=" + entries + ", identity=" + identity + ", loadedSids="
				+ loadedSids + "]";
	}
	
	private void verifyAceIndexExists(final int aceIndex) {
		if (aceIndex < 0) {
			throw new NotFoundException("aceIndex must be greater than or equal to zero");
		}
		if (aceIndex >= this.entries.size()) {
			throw new NotFoundException("aceIndex must refer to an index of the AccessControlEntry list. " +
					"List size is " + entries.size() + ", index was " + aceIndex);
		}
	}

}
