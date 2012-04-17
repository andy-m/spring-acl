package net.projectmonkey.spring.acl.repository;

import java.util.List;
import java.util.Map;

import net.projectmonkey.spring.acl.entity.SimpleMutableAcl;
import net.projectmonkey.spring.acl.service.SimpleACLService;

import org.springframework.security.acls.domain.SimpleAcl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
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
 * Interface for Repository implementations allowing users to utilise
 * the {@link SimpleAcl} and {@link SimpleACLService} with whatever
 * database implementations they wish.
 * 
 * @author Andy Moody
 */
public interface ACLUpdateRepository {
	
	/* Read only methods */
	Map<ObjectIdentity, Acl> getAclsById(final List<ObjectIdentity> objectIdentities, final List<Sid> sids);
	
	/* Write methods */
	/**
	 * Creates a new acl for the given identity, if one does not already exist
	 * @param identity
	 * @return the created acl
	 */
	SimpleMutableAcl create(ObjectIdentity identity);
	
	/**
	 * Updates the specified acl, if it exists
	 * @param acl
	 */
	void update(final MutableAcl acl);

	/**
	 * Deletes the specified acl, if it exists
	 * @param acl
	 */
	void delete(ObjectIdentity identity);

	/**
	 * Checks if an acl exists for the supplied identity.
	 * @param identity
	 * @return true if an acl exists for the supplied identity, false otherwise
	 */
	boolean isThereAnAclFor(ObjectIdentity identity);

}
