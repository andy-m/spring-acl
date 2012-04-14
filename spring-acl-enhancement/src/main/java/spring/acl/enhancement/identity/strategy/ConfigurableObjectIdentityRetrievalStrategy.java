package spring.acl.enhancement.identity.strategy;

import java.io.Serializable;

import org.springframework.security.acls.domain.IdentityUnavailableException;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import spring.acl.enhancement.identity.mapping.BasicSecureObjectMapping;
import spring.acl.enhancement.identity.mapping.SecureObjectMapping;
import spring.acl.util.reflect.MethodUtil;


/**
 * Object identity retrieval strategy
 * allowing us to specify which, if any, method should be used
 * for retrieving the id.
 * 
 * If no identifierMethod is configured the domain object itself
 * is used as the identifier.
 * 
 * @author Andy Moody
 */
public class ConfigurableObjectIdentityRetrievalStrategy implements ExtendedObjectIdentityRetrievalStrategy {
	
	private final String identifierMethod;
	
	public ConfigurableObjectIdentityRetrievalStrategy() {
		this(null);
	}
	
	public ConfigurableObjectIdentityRetrievalStrategy(final String identifierMethod) {
		this.identifierMethod = identifierMethod;
	}

	@Override
	public ObjectIdentity getObjectIdentity(final Object object) {
		Assert.notNull(object, "object cannot be null");
		SecureObjectMapping mapping = new BasicSecureObjectMapping(object);
        return getObjectIdentity(mapping);
	}
	
	@Override
	public ObjectIdentity getObjectIdentity(final SecureObjectMapping mapping) {
		Assert.notNull(mapping, "mapping cannot be null");

		Class<?> identityType = mapping.getSecuredClass();
		Object id = mapping.getDomainObject();
		Assert.notNull(identityType, "identity type cannot be null");
		Assert.notNull(id, "domain object cannot be null");
		
		if(StringUtils.hasText(identifierMethod)){
			try {
				id = MethodUtil.invoke(id, identifierMethod);
			} catch (Exception e) {
				throw new IdentityUnavailableException("Could not extract identity from object " + id, e);
			}
			Assert.notNull(id, identifierMethod+"() is required to return a non-null value");
		}
		
		Assert.isInstanceOf(Serializable.class, id, "Getter must provide a return value of type Serializable");
		return new ObjectIdentityImpl(identityType, (Serializable) id);
	}

}
