package spring.acl.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

import spring.acl.repository.ACLUpdateRepository;

/**
 * Implementation of MutableAclService which delegates
 * the majority of responsibility to the configured
 * repository. 
 * 
 * @author Andy Moody
 */
public class SimpleACLService implements MutableAclService {

	private final ACLUpdateRepository aclRepository;

	public SimpleACLService(final ACLUpdateRepository aclRepository) {
		this.aclRepository = aclRepository;
	}

	@Override
	public List<ObjectIdentity> findChildren(final ObjectIdentity parentIdentity) {
		// we don't support children for the time being.
		return null;
	}

	@Override
	public Acl readAclById(final ObjectIdentity object) throws NotFoundException {
		return readAclById(object, null);
	}

	@Override
	public Acl readAclById(final ObjectIdentity object, final List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Arrays.asList(object), sids);
		Assert.isTrue(map.containsKey(object), "There should have been an Acl entry for ObjectIdentity " + object);

		return map.get(object);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(final List<ObjectIdentity> objects) throws NotFoundException {
		return readAclsById(objects, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(final List<ObjectIdentity> objects, final List<Sid> sids)
			throws NotFoundException {
		Map<ObjectIdentity, Acl> result = aclRepository.getAclsById(objects, sids);

		/*
		 * Check we found an ACL for every requested object. Where ACL's do not
		 * exist for some objects throw a suitable exception.
		 */
		Set<ObjectIdentity> remainingIdentities = new HashSet<ObjectIdentity>(objects);
		if (result.size() != remainingIdentities.size())
		{
			remainingIdentities.removeAll(remainingIdentities);
			throw new NotFoundException("Unable to find ACL information for object identities '" + remainingIdentities + "'");
		}
		return result;
	}

	@Override
	public MutableAcl createAcl(final ObjectIdentity objectIdentity) throws AlreadyExistsException {
		return aclRepository.create(objectIdentity);
	}

	@Override
	public void deleteAcl(final ObjectIdentity objectIdentity, final boolean deleteChildren) throws ChildrenExistException {
		aclRepository.delete(objectIdentity);
	}

	@Override
	public MutableAcl updateAcl(final MutableAcl acl) throws NotFoundException {
		aclRepository.update(acl);
		return acl;
	}

}
