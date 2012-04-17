package spring.acl.enhancement.identity.mapping;

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
 * Basic implementation of {@link SecureObjectMapping}
 * used to wrap a domainObject so it can be passed to the 
 * same {@link ExtendedObjectIdentityRetrievalStrategy#getObjectIdentity(SecureObjectMapping mapping)}
 * method
 *
 * @author Andy Moody
 */
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
