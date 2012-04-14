package spring.acl.enhancement.identity.mapping;

import org.springframework.util.StringUtils;

import spring.acl.util.reflect.MethodUtil;

/**
 * Implementation of ${@link SecureObjectMapping} which will return
 * the results of executing the specified internal method against the
 * provided domain object instead of returning the domain object itself. 
 * 
 * @author Andy Moody
 */
public class SecureObjectMappingWithInternalMethod implements SecureObjectMapping {

	private final String internalMethod;
	private final Object domainObject;
	private final Class<?> securedClass;

	public SecureObjectMappingWithInternalMethod(final Object domainObject, final Class<?> securedClass,
			final String internalMethod) {
		this.domainObject = domainObject;
		this.securedClass = securedClass;
		this.internalMethod = internalMethod;
	}

	public SecureObjectMappingWithInternalMethod(final Object domainObject, final String internalMethod) {
		this.domainObject = domainObject;
		this.securedClass = domainObject == null ? null : domainObject.getClass();
		this.internalMethod = internalMethod;
	}

	@Override
	public Object getDomainObject() {
		Object domainObject = this.domainObject;
		if (domainObject != null)
		{
			// Evaluate if we are required to use an inner domain object
			if (StringUtils.hasText(this.internalMethod))
			{
				domainObject = MethodUtil.invoke(domainObject, this.internalMethod);
			}
		}
		return domainObject;
	}

	@Override
	public Class<?> getSecuredClass() {
		return securedClass;
	}
	
	public String getInternalMethod() {
		return internalMethod;
	}
	
	public Object getOriginalDomainObject(){
		return domainObject;
	}

}