package spring.acl.enhancement.identity.strategy;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.security.acls.model.ObjectIdentity;

import spring.acl.enhancement.identity.mapping.SecureObjectMapping;
import spring.acl.enhancement.identity.mapping.SimpleTestClass;
import spring.acl.enhancement.identity.strategy.ConfigurableObjectIdentityRetrievalStrategy;
import spring.acl.enhancement.identity.strategy.DefaultObjectIdentityRetrievalStrategy;




public class TestConfigurableObjectIdentityRetrievalStrategy {
	
	private ConfigurableObjectIdentityRetrievalStrategy underTest;
	@Mock
	private SecureObjectMapping mapping;
	
	@Before
	public void setUp(){
		initMocks(this);
		underTest = new ConfigurableObjectIdentityRetrievalStrategy();
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Test
	public void domainObjectAndSecuredClassUsedIfNoIdentifierMethodSpecified(){
		SimpleTestClass domainObject = new SimpleTestClass();
		Class clazz = SimpleTestClass.class;
		when(mapping.getDomainObject()).thenReturn(domainObject);
		when(mapping.getSecuredClass()).thenReturn(clazz);
		ObjectIdentity returned = underTest.getObjectIdentity(mapping);
		assertEquals(clazz.getName(), returned.getType());
		assertEquals(domainObject, returned.getIdentifier());
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Test
	public void internalMethodCallResultAndSecuredClassUsedIfIdentifierMethodSpecified(){
		underTest = new ConfigurableObjectIdentityRetrievalStrategy("getId");
		SimpleTestClass domainObject = new SimpleTestClass();
		Class clazz = SimpleTestClass.class;
		when(mapping.getDomainObject()).thenReturn(domainObject);
		when(mapping.getSecuredClass()).thenReturn(clazz);
		ObjectIdentity returned = underTest.getObjectIdentity(mapping);
		assertEquals(clazz.getName(), returned.getType());
		assertEquals(domainObject.getId(), returned.getIdentifier());
	}
	
	@SuppressWarnings({ "rawtypes"})
	@Test
	public void domainObjectAndSecuredClassUsedIfNoIdentifierMethodSpecifiedWhenUsingObject(){
		SimpleTestClass domainObject = new SimpleTestClass();
		Class clazz = SimpleTestClass.class;
		ObjectIdentity returned = underTest.getObjectIdentity(domainObject);
		assertEquals(clazz.getName(), returned.getType());
		assertEquals(domainObject, returned.getIdentifier());
	}
	
	@SuppressWarnings({ "rawtypes"})
	@Test
	public void internalMethodCallResultAndSecuredClassUsedIfIdentifierMethodSpecifiedWhenUsingObject(){
		// the DefaultObjectIdentityRetrievalStrategy uses getId as per the existing Spring implementation
		underTest = new DefaultObjectIdentityRetrievalStrategy(); 
		SimpleTestClass domainObject = new SimpleTestClass();
		Class clazz = SimpleTestClass.class;
		ObjectIdentity returned = underTest.getObjectIdentity(domainObject);
		assertEquals(clazz.getName(), returned.getType());
		assertEquals(domainObject.getId(), returned.getIdentifier());
	}

}
