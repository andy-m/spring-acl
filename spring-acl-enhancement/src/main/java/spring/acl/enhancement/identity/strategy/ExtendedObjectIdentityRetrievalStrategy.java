package spring.acl.enhancement.identity.strategy;

import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;

import spring.acl.enhancement.identity.mapping.SecureObjectMapping;

/**
 * Extension of {@link ObjectIdentityRetrievalStrategy}
 * which allows us to get an {@link ObjectIdentity} from a 
 * {@link SecureObjectMapping} as well as from a domain object.
 * 
 * Thus allowing us to separate the secured object from the object
 * we use to check security against that object - e.g. being able to
 * check the security of a domain object by simply supplying a String id.
 * 
 * @author Andy Moody
 */
public interface ExtendedObjectIdentityRetrievalStrategy extends ObjectIdentityRetrievalStrategy{

	ObjectIdentity getObjectIdentity(SecureObjectMapping mapping);
	
}
