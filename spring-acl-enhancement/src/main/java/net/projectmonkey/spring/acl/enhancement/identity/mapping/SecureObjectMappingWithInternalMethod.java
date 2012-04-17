package net.projectmonkey.spring.acl.enhancement.identity.mapping;

import net.projectmonkey.spring.acl.util.reflect.MethodUtil;

import org.springframework.util.StringUtils;


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
 * Implementation of ${@link SecureObjectMapping} which will return
 * the results of executing the specified internal method against the
 * provided domain object instead of returning the domain object itself. 
 * 
 * If no internalMethod is specified the domain object itself will be returned.
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