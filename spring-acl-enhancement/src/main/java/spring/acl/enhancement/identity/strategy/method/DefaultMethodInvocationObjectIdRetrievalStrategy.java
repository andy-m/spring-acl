package spring.acl.enhancement.identity.strategy.method;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.StringUtils;

import spring.acl.enhancement.annotation.SecuredAgainst;
import spring.acl.enhancement.annotation.SecuredId;
import spring.acl.enhancement.identity.mapping.SecureObjectMapping;
import spring.acl.enhancement.identity.mapping.SecureObjectMappingWithInternalMethod;
import spring.acl.enhancement.identity.strategy.DefaultObjectIdentityRetrievalStrategy;
import spring.acl.enhancement.identity.strategy.ExtendedObjectIdentityRetrievalStrategy;

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
/**
 * Default invocation of {@link MethodInvocationObjectIdRetrievalStrategy} 
 * which simplifies, and makes more flexible, the process of retrieving secured object identifiers. 
 * This class will check for an {@link SecuredAgainst} annotation on the method. If one is
 * present the class defined in this will be the one we process. If no
 * {@link SecuredAgainst} annotation is present then we fall back to the
 * optional processDomainObjectClass.
 * 
 * It will identify the first appropriate parameter to use using the following
 * criteria (in priority order):
 * 
 * 1) Does this parameter have the {@link SecuredId} annotation with a class
 * from which the configured class can be assigned.
 * 
 * 2) Is the configured class assignable from the class of the parameter.
 * 
 * So any parameter matching criteria 1) will be used in preference to a
 * parameter matching criteria 2 even if the parameter matching criteria 2 is
 * earlier in the argument list.
 * 
 * The optional internalMethod parameter is then used to invoke a method on the resolved
 * parameter if it is present. Otherwise it will try to use the parameter value itself as the id.
 * 
 * The internalMethod may also be configured on the {@link SecuredId} annotation. If there is an
 * internalMethod configured on the annotation it will take precedence over any configured in this
 * class.
 * 
 * throws AuthorizationServiceException 
 * if 
 * no class is provided either in a {@link SecuredAgainst} annotation or the processDomainObjectClass field. 
 * or
 * no suitable parameter can be found 
 * or 
 * the configured internalMethod is inaccessible or uninvokable.
 * 
 * @author Andy Moody
 */
public class DefaultMethodInvocationObjectIdRetrievalStrategy implements MethodInvocationObjectIdRetrievalStrategy{

	private ExtendedObjectIdentityRetrievalStrategy mappedIdentityRetrievalStrategy = new DefaultObjectIdentityRetrievalStrategy();
	private Class<?> processDomainObjectClass;
	private String internalMethod;
	
	public DefaultMethodInvocationObjectIdRetrievalStrategy(){}
	
	public DefaultMethodInvocationObjectIdRetrievalStrategy(final ExtendedObjectIdentityRetrievalStrategy mappedIdentityRetrievalStrategy, 
			final Class<?> processDomainObjectClass, final String internalMethod) {
		this.mappedIdentityRetrievalStrategy = mappedIdentityRetrievalStrategy;
		this.processDomainObjectClass = processDomainObjectClass;
		this.internalMethod = internalMethod;
	}

	@Override
	public ObjectIdentity getObjectIdentity(final MethodInvocation invocation) {
		SecureObjectMapping secureObjectMapping = locateSecureObjectMapping(invocation);
        ObjectIdentity identity = null;
        if(secureObjectMapping != null)
    	{
        	identity = mappedIdentityRetrievalStrategy.getObjectIdentity(secureObjectMapping);
    	}
        return identity;
	}
	
	/**
	 * Extension Point: Locate the secure object mapping from the method invocation.
	 * This is the main purpose of the class so overriding this allows users to move
	 * completely away from the {@link SecuredAgainst} and {@link SecuredId} annotations. 
	 * @param invocation
	 * @return
	 */
	protected SecureObjectMapping locateSecureObjectMapping(final MethodInvocation invocation) {
		SecureObjectMapping matchingSecuredIdParamValue = null;
		SecureObjectMapping matchingAssignable = null;

		Method method = invocation.getMethod();
		Class<?> securedClass = resolveSecuredClass(method);

		Class<?>[] parameterTypes = method.getParameterTypes();
		Object[] arguments = invocation.getArguments();
		Annotation[][] parameterAnnotations = method.getParameterAnnotations();

		
		for (int i = 0; i < arguments.length && matchingSecuredIdParamValue == null; i++)
		{
			Object argument = arguments[i];

			Annotation[] annotations = parameterAnnotations[i];
			SecuredId parameterAnnotation = locateAnnotation(annotations);
			if (parameterAnnotation != null)
			{
				String internalMethod = resolveInternalMethod(parameterAnnotation);
				matchingSecuredIdParamValue = new SecureObjectMappingWithInternalMethod(argument, securedClass, internalMethod);
				break; // we've found a parameter which specifies it provides the id, so break;
			}

			Class<?> parameterType = parameterTypes[i];

			if (matchingAssignable == null && securedClass.isAssignableFrom(parameterType))
			{
				//here we use the actual argument type as the secured class since we are an instance of the required type.
				matchingAssignable = new SecureObjectMappingWithInternalMethod(argument, internalMethod);
			}
		}
		return firstNonNull(matchingSecuredIdParamValue, matchingAssignable);
	}
	
	/**
	 * Extension point: Locate the class we want to look up acl's against for the method we're securing. 
	 * @param method
	 * @return
	 */
	protected Class<?> resolveSecuredClass(final Method method) {
		Class<?> classToFind = processDomainObjectClass;
		SecuredAgainst securedAgainst = method.getAnnotation(SecuredAgainst.class);
		if (securedAgainst != null && securedAgainst.value() != null)
		{
			classToFind = securedAgainst.value();
		}
		if (classToFind == null)
		{
			throw new AuthenticationServiceException("No secured class specified for method " + method);
		}
		return classToFind;
	}

	private SecureObjectMapping firstNonNull(final SecureObjectMapping... values) {
		for (SecureObjectMapping value : values)
		{
			if(value != null){
				return value;
			}
		}
		return null;
	}

	private String resolveInternalMethod(final SecuredId annotation) {
		String internalMethod = annotation.internalMethod();
		if (!StringUtils.hasText(internalMethod))
		{
			internalMethod = this.internalMethod;
		}
		return internalMethod;
	}

	private SecuredId locateAnnotation(final Annotation[] annotations) {
		SecuredId toReturn = null;
		for (Annotation annotation : annotations)
		{
			
			if (annotation.annotationType().equals(SecuredId.class))
			{
				toReturn = (SecuredId) annotation;
				break;// we've found our annotation so exit
			}
		}
		return toReturn;
	}

	/************************************* Getters and Setters ***********************************************/
	
	public void setMappedIdentityRetrievalStrategy(final ExtendedObjectIdentityRetrievalStrategy mappedIdentityRetrievalStrategy) {
		this.mappedIdentityRetrievalStrategy = mappedIdentityRetrievalStrategy;
	}
	
	public void setProcessDomainObjectClass(final Class<?> processDomainObjectClass) {
		this.processDomainObjectClass = processDomainObjectClass;
	}
	
	/**
	 * Optionally specifies a method of the domain object that will be used to
	 * obtain a contained domain object. That contained domain object will be
	 * used for the ACL evaluation. This is useful if a domain object contains a
	 * parent that an ACL evaluation should be targeted for, instead of the
	 * child domain object (which perhaps is being created and as such does not
	 * yet have any ACL permissions)
	 * 
	 * @return <code>null</code> to use the domain object, or the name of a
	 *         method (that requires no arguments) that should be invoked to
	 *         obtain an <code>Object</code> which will be the domain object
	 *         used for ACL evaluation
	 */
	public void setInternalMethod(final String internalMethod) {
		this.internalMethod = internalMethod;
	}

}

