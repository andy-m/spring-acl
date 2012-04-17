package net.projectmonkey.spring.acl.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.projectmonkey.spring.acl.entity.SimpleMutableAcl;
import net.projectmonkey.spring.acl.repository.ACLUpdateRepository;

import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
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
 * Implementation of {@link SimpleMutableAclService} which will
 * retrieve values from the configured repository and perform
 * the necessary validation on inputs and outputs.
 * 
 * @author Andy Moody
 */
public class SimpleACLService implements SimpleMutableAclService {

	private final ACLUpdateRepository aclRepository;

	public SimpleACLService(final ACLUpdateRepository aclRepository) {
		this.aclRepository = aclRepository;
	}

	@Override
	public List<ObjectIdentity> findChildren(final ObjectIdentity parentIdentity) {
		// we don't support children for the time being.
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.security.acls.model.AclService#readAclById(org.springframework.security.acls.model.ObjectIdentity)
	 */
	@Override
	public Acl readAclById(final ObjectIdentity identity) throws NotFoundException {
		return readAclById(identity, null);
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.security.acls.model.AclService#readAclById(org.springframework.security.acls.model.ObjectIdentity, java.util.List)
	 */
	@Override
	public Acl readAclById(final ObjectIdentity identity, final List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Arrays.asList(identity), sids);
		return map.get(identity);
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.security.acls.model.AclService#readAclsById(java.util.List)
	 */
	@Override
	public Map<ObjectIdentity, Acl> readAclsById(final List<ObjectIdentity> identities) throws NotFoundException {
		return readAclsById(identities, null);
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.security.acls.model.AclService#readAclsById(java.util.List, java.util.List)
	 */
	@Override
	public Map<ObjectIdentity, Acl> readAclsById(final List<ObjectIdentity> identities, final List<Sid> sids)
			throws NotFoundException {
		Assert.notNull(identities, "At least one Object Identity required");
		Assert.isTrue(identities.size() > 0, "At least one Object Identity required");
		Assert.noNullElements(identities.toArray(new ObjectIdentity[0]), "Null object identities are not permitted");
		
		Map<ObjectIdentity, Acl> result = aclRepository.getAclsById(identities, sids);

		/*
		 * Check we found an ACL for every requested object. Where ACL's do not
		 * exist for some objects throw a suitable exception.
		 */
		Set<ObjectIdentity> remainingIdentities = new HashSet<ObjectIdentity>(identities);
		if (result.size() != remainingIdentities.size())
		{
			remainingIdentities.removeAll(result.keySet());
			throw new NotFoundException("Unable to find ACL information for object identities '" + remainingIdentities + "'");
		}
		return result;
	}

	/*
	 * (non-Javadoc)
	 * @see spring.acl.service.SimpleMutableAclService#createAcl(org.springframework.security.acls.model.ObjectIdentity)
	 */
	@Override
	public SimpleMutableAcl createAcl(final ObjectIdentity identity) throws AlreadyExistsException {
		Assert.notNull(identity, "identity must not be null");
		if (aclRepository.isThereAnAclFor(identity))
		{
			throw new AlreadyExistsException("Acl already exists for identity " + identity
					+ " this implementation requires globally unique identifiers");
		}
		return aclRepository.create(identity);
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.security.acls.model.MutableAclService#deleteAcl(org.springframework.security.acls.model.ObjectIdentity, boolean)
	 */
	@Override
	public void deleteAcl(final ObjectIdentity identity, final boolean deleteChildren) throws ChildrenExistException {
		Assert.notNull(identity, "identity must not be null");
		aclRepository.delete(identity);
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.security.acls.model.MutableAclService#updateAcl(org.springframework.security.acls.model.MutableAcl)
	 */
	@Override
	public MutableAcl updateAcl(final MutableAcl acl) throws NotFoundException {
		verifyAclExists(acl);
		aclRepository.update(acl);
		return acl;
	}
	
	/*
	 * (non-Javadoc)
	 * @see spring.acl.service.SimpleMutableAclService#updateAcl(org.springframework.security.acls.domain.SimpleMutableAcl)
	 */
	@Override
	public SimpleMutableAcl updateAcl(final SimpleMutableAcl acl) throws NotFoundException {
		verifyAclExists(acl);
		aclRepository.update(acl);
		return acl;
	}
	
	private void verifyAclExists(final MutableAcl acl) {
		ObjectIdentity identity = acl.getObjectIdentity();
		if (!aclRepository.isThereAnAclFor(identity))
		{
			throw new NotFoundException("Acl does not exist for object identity " + identity);
		}
	}

}
