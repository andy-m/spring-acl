package spring.acl.repository;

import java.util.List;
import java.util.Map;

import org.springframework.security.acls.domain.SimpleAcl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

import spring.acl.service.SimpleACLService;

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
	 * @throws AlreadyExistsException if an acl already exists for the supplied identity.
	 */
	MutableAcl create(ObjectIdentity identity);
	
	/**
	 * Updates the specified acl, if it exists
	 * @param acl
	 * @throws NotFoundException if the supplied acl is not already persisted
	 */
	void update(final MutableAcl acl);

	/**
	 * Deletes the specified acl, if it exists
	 * @param acl
	 */
	void delete(ObjectIdentity identity);

}
