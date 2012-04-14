package spring.acl.enhancement.identity.strategy.method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.acls.model.ObjectIdentity;

/**
 * Immitates the ObjectIdentityRetrievalStrategy from the spring framework
 * but seeks to resolve the ObjectIdentity from the method invocation
 * rather than a domain object.
 * 
 * This is more flexible since it allowes our strategies to determine
 * exactly how ObjectIdentities should be retrieved - rather than relying
 * on the existing spring domain object resolution.
 * 
 * Implementations may return null if no identity is available;
 * 
 * @author Andy Moody
 */
public interface MethodInvocationObjectIdRetrievalStrategy {

	 ObjectIdentity getObjectIdentity(MethodInvocation invocation);
	 
}
