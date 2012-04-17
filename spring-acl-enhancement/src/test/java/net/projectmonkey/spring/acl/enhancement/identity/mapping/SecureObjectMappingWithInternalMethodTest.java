package net.projectmonkey.spring.acl.enhancement.identity.mapping;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import net.projectmonkey.spring.acl.enhancement.identity.mapping.SecureObjectMappingWithInternalMethod;

import org.junit.Test;

/*
	Copyright 2012 Andy Moody
	
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
	
	    http://www.apache.org/licenses/LICENSE-2.0
	
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

public class SecureObjectMappingWithInternalMethodTest {

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
