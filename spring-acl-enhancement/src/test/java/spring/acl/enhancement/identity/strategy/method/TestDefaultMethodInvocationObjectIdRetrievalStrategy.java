package spring.acl.enhancement.identity.strategy.method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.authentication.AuthenticationServiceException;

import spring.acl.enhancement.identity.mapping.SecureObjectMappingWithInternalMethod;
import spring.acl.enhancement.identity.strategy.ExtendedObjectIdentityRetrievalStrategy;
import spring.acl.enhancement.identity.strategy.method.sample.TestClass;
import spring.acl.enhancement.identity.strategy.method.sample.TestClass2;

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

public class TestDefaultMethodInvocationObjectIdRetrievalStrategy {

	private static final String INTERNAL_METHOD = "someInternalMethod";
	private DefaultMethodInvocationObjectIdRetrievalStrategy underTest;
	@Mock
	private ExtendedObjectIdentityRetrievalStrategy mappedIdentityRetrievalStrategy;
	@Mock
	private MethodInvocation invocation;
	@Mock
	private ObjectIdentity identity;
	
	@Before
	public void setUp(){
		initMocks(this);
		underTest = new DefaultMethodInvocationObjectIdRetrievalStrategy(mappedIdentityRetrievalStrategy, null, INTERNAL_METHOD);
	}
	
	@Test(expected = AuthenticationServiceException.class)
	public void exceptionThrownIfNoClassProvidedAndSecuredAgainstAnnotationNotPresent() throws SecurityException, NoSuchMethodException{
		stubMethodInvocation("methodWithNoSecuredAgainst", null);
		underTest.getObjectIdentity(invocation);
	}
	
	@Test
	public void nullReturnedIfUsingProcessDomainObjectClassAndNoArgumentsForMethod() throws SecurityException, NoSuchMethodException{
		stubMethodInvocation("methodWithNoSecuredAgainst", null);
		underTest.setProcessDomainObjectClass(TestClass.class);
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertNull(returned);
	}
	
	@Test
	public void nullReturnedIfUsingSecuredAgainstClassAndNoArgumentsForMethod() throws SecurityException, NoSuchMethodException{
		stubMethodInvocation("methodWithSecuredAgainstAndNoParams", null);
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertNull(returned);
	}
	
	@Test
	public void nullReturnedWhenNoMatchingParamsExistUsingProcessDomainObjectClass() throws SecurityException, NoSuchMethodException{
		stubMethodInvocation("methodWithNoSecuredAgainstAndNoMatchingParams", new Class<?>[]{Object.class}, new Object());
		underTest.setProcessDomainObjectClass(TestClass.class);
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertNull(returned);
	}
	
	@Test
	public void nullReturnedWhenNoMatchingParamsExistUsingSecuredAgainstConfig() throws SecurityException, NoSuchMethodException{
		stubMethodInvocation("methodWithSecuredAgainstAndNoMatchingParams", new Class<?>[]{Object.class}, new Object());
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertNull(returned);
	}
	
	@Test
	public void argumentReturnedWhenSecuredIdParamsExistUsingProcessDomainObjectClass() throws SecurityException, NoSuchMethodException{
		final Object arg = new Object();
		stubMethodInvocation("methodWithNoSecuredAgainstAndParamsWhichMatchBecauseOfSecuredId", new Class<?>[]{Object.class}, arg);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg));
		underTest.setProcessDomainObjectClass(TestClass.class);
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}
	
	@Test
	public void argumentReturnedWhenSecuredIdParamsExistUsingSecuredAgainstConfig() throws SecurityException, NoSuchMethodException{
		Object arg = new Object();
		stubMethodInvocation("methodWithSecuredAgainstAndParamsWhichMatchBecauseOfSecuredId", new Class<?>[]{Object.class}, arg);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg));
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}
	
	@Test
	public void argumentReturnedWhenAssignableParamsExistUsingProcessDomainObjectClass() throws SecurityException, NoSuchMethodException{
		final TestClass2 arg = new TestClass2();
		stubMethodInvocation("methodWithNoSecuredAgainstAndParamsWhichMatchBecauseOfAssignable", new Class<?>[]{TestClass.class}, arg);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg, TestClass2.class));
		underTest.setProcessDomainObjectClass(TestClass.class);
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}
	
	@Test
	public void argumentReturnedWhenAssignableParamsExistUsingSecuredAgainstConfig() throws SecurityException, NoSuchMethodException{
		TestClass2 arg = new TestClass2();
		stubMethodInvocation("methodWithSecuredAgainstAndParamsWhichMatchBecauseOfAssignable", new Class<?>[]{TestClass.class}, arg);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg, TestClass2.class));
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}
	
	@Test
	public void firstSecuredIdParamReturnedEvenIfAssignableParamIsEarlierInTheArgumentList() throws SecurityException, NoSuchMethodException{
		TestClass2 arg1 = new TestClass2();
		Object arg2 = new Object();
		Object arg3 = new Object();
		stubMethodInvocation("methodWithMultipleSecuredIdsAndAssignables", new Class<?>[]{TestClass.class, Object.class, Object.class}, arg1, arg2, arg3);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg2));
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}
	
	@Test
	public void firstAssignableParamReturnedIfMultipleAssignableParamsExistAndNoSecuredIdParamsArePresent() throws SecurityException, NoSuchMethodException{
		TestClass2 arg1 = new TestClass2();
		TestClass2 arg2 = new TestClass2();
		stubMethodInvocation("methodWithMultipleAssignables", new Class<?>[]{TestClass.class, TestClass.class}, arg1, arg2);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg1, TestClass2.class));
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}
	
	@Test
	public void internalMethodFromSecuredIdAnnotationTakesPrecedenceOverTheInternalMethodConfiguredHere() throws SecurityException, NoSuchMethodException{
		TestClass2 arg1 = new TestClass2();
		stubMethodInvocation("methodWithSecuredIdDefiningInternalMethod", new Class<?>[]{TestClass.class}, arg1);
		when(mappedIdentityRetrievalStrategy.getObjectIdentity(Mockito.isA(SecureObjectMappingWithInternalMethod.class))).thenAnswer(assertMappingAndReturnIdentity(arg1, TestClass.class, "someOtherMethod"));
		ObjectIdentity returned = underTest.getObjectIdentity(invocation);
		assertEquals(identity, returned);
	}

	private void stubMethodInvocation(final String methodName, final Class<?>[] parameterTypes, final Object...arguments) throws SecurityException, NoSuchMethodException{
		Method method = TestClass.class.getMethod(methodName, parameterTypes);
		when(invocation.getMethod()).thenReturn(method);
		when(invocation.getArguments()).thenReturn(arguments);
	}

	private Answer<ObjectIdentity> assertMappingAndReturnIdentity(final Object expectedDomainObject) {
		return assertMappingAndReturnIdentity(expectedDomainObject, TestClass.class);
	}
	
	private Answer<ObjectIdentity> assertMappingAndReturnIdentity(final Object expectedDomainObject, final Class<?> securedClass) {
		return assertMappingAndReturnIdentity(expectedDomainObject, securedClass, INTERNAL_METHOD);
	}
	
	private Answer<ObjectIdentity> assertMappingAndReturnIdentity(final Object expectedDomainObject, final Class<?> securedClass, final String internalMethod) {
		return new Answer<ObjectIdentity>() {
			@Override
			public ObjectIdentity answer(final InvocationOnMock invocation) throws Throwable {
				Object[] arguments = invocation.getArguments();
				assertEquals(1, arguments.length);
				SecureObjectMappingWithInternalMethod mapping = (SecureObjectMappingWithInternalMethod) arguments[0];
				assertEquals(expectedDomainObject, mapping.getOriginalDomainObject());
				assertEquals(securedClass, mapping.getSecuredClass());
				assertEquals(internalMethod, mapping.getInternalMethod());
				return identity;
			}
		};
	}
	
}