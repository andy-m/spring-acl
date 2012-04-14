package spring.acl.enhancement.identity.mapping;

/**
 * Interface allowing us to separate the object which
 * is the identifier or contains the identifier from the
 * class we want to check security against.
 * 
 * This allows us to do nice things like checking security
 * against the id of an entity without needing to load the
 * entity first.
 * 
 * @author Andy Moody
 */
public interface SecureObjectMapping {
	
	Object getDomainObject();
	Class<?> getSecuredClass();
	
}
