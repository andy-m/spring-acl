package spring.acl.enhancement.identity.mapping;

public class BasicSecureObjectMapping implements SecureObjectMapping{

	private final Object domainObject;

	public BasicSecureObjectMapping(final Object domainObject){
		this.domainObject = domainObject;
	}
	
	@Override
	public Object getDomainObject() {
		return domainObject;
	}

	@Override
	public Class<?> getSecuredClass() {
		return domainObject.getClass();
	}

}
