package spring.acl.enhancement.identity.mapping;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import spring.acl.enhancement.identity.mapping.SecureObjectMappingWithInternalMethod;



public class TestSecureObjectMappingWithInternalMethod {

	@Test
	public void originalDomainObjectReturnedIfNoInternalMethodIsSpecified(){
		SimpleTestClass domainObject = new SimpleTestClass();
		SecureObjectMappingWithInternalMethod underTest = new SecureObjectMappingWithInternalMethod(domainObject, " ");
		assertEquals(domainObject, underTest.getDomainObject());
		assertEquals(SimpleTestClass.class, underTest.getSecuredClass());
	}
	
	@Test
	public void resultOfMethodInvokationReturnedIfValidInternalMethodIsSpecified(){
		SimpleTestClass domainObject = new SimpleTestClass();
		SecureObjectMappingWithInternalMethod underTest = new SecureObjectMappingWithInternalMethod(domainObject, "getId");
		assertEquals(domainObject.getId(), underTest.getDomainObject());
		assertEquals(SimpleTestClass.class, underTest.getSecuredClass());
	}
	
	@Test
	public void specifiedSecuredClassReturnedIfSpecifiedOnConstruction(){
		SimpleTestClass domainObject = new SimpleTestClass();
		SecureObjectMappingWithInternalMethod underTest = new SecureObjectMappingWithInternalMethod(domainObject, Object.class, "getId");
		assertEquals(domainObject.getId(), underTest.getDomainObject());
		assertEquals(Object.class, underTest.getSecuredClass());
	}
	
	@Test
	public void nullDomainObjectAndClassReturnedIfNullDomainObjectPassed(){
		SecureObjectMappingWithInternalMethod underTest = new SecureObjectMappingWithInternalMethod(null, "getId");
		assertNull(underTest.getDomainObject());
		assertNull(underTest.getSecuredClass());
	}
	
}
