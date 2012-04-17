package net.projectmonkey.spring.acl.enhancement.identity.strategy;

import java.io.Serializable;

import net.projectmonkey.spring.acl.enhancement.identity.mapping.BasicSecureObjectMapping;
import net.projectmonkey.spring.acl.enhancement.identity.mapping.SecureObjectMapping;
import net.projectmonkey.spring.acl.util.reflect.MethodUtil;

import org.springframework.security.acls.domain.IdentityUnavailableException;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.util.Assert;
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
 * Object identity retrieval strategy
 * allowing us to specify which, if any, method should be used
 * for retrieving the id.
 * 
 * If no identifierMethod is configured the domain object itself
 * is assumed to be the identifier.
 * 
 * @author Andy Moody
 */
public class ConfigurableObjectIdentityRetrievalStrategy implements ExtendedObjectIdentityRetrievalStrategy {
	
	private final String identifierMethod;
	
	public ConfigurableObjectIdentityRetrievalStrategy() {
		this(null);
	}
	
	public ConfigurableObjectIdentityRetrievalStrategy(final String identifierMethod) {
		this.identifierMethod = identifierMethod;
	}

	@Override
	public ObjectIdentity getObjectIdentity(final Object object) {
		Assert.notNull(object, "object cannot be null");
		SecureObjectMapping mapping = new BasicSecureObjectMapping(object);
        return getObjectIdentity(mapping);
	}
	
	@Override
	public ObjectIdentity getObjectIdentity(final SecureObjectMapping mapping) {
		Assert.notNull(mapping, "mapping cannot be null");

		Class<?> identityType = mapping.getSecuredClass();
		Object id = mapping.getDomainObject();
		Assert.notNull(identityType, "identity type cannot be null");
		Assert.notNull(id, "domain object cannot be null");
		
		if(StringUtils.hasText(identifierMethod)){
			try {
				id = MethodUtil.invoke(id, identifierMethod);
			} catch (Exception e) {
				throw new IdentityUnavailableException("Could not extract identity from object " + id, e);
			}
			Assert.notNull(id, identifierMethod+"() is required to return a non-null value");
		}
		
		Assert.isInstanceOf(Serializable.class, id, "Getter must provide a return value of type Serializable");
		return new ObjectIdentityImpl(identityType, (Serializable) id);
	}

}
