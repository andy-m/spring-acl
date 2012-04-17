package net.projectmonkey.spring.acl.factory;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

/*
 * 
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
 * Factory bean allowing configuration of an {@link AclAuthorizationStrategyImpl}
 * using simple String constructor args representing the required authorities. 
 * 
 * @author Andy Moody
 */
public class DefaultAclAuthorizationStrategyFactoryBean implements FactoryBean<AclAuthorizationStrategyImpl>{

	private final String[] authorisations;

	public DefaultAclAuthorizationStrategyFactoryBean(final String...authorisations){
		Assert.notEmpty(authorisations);
		Assert.isTrue(authorisations.length == 1 || authorisations.length == 3, "Either 1 or 3 authorization strings must be provided");
		this.authorisations = authorisations;
	}
	
	@Override
	public AclAuthorizationStrategyImpl getObject() {
		GrantedAuthority[] auths = new GrantedAuthority[authorisations.length];
		for (int i = 0; i < authorisations.length; i++)
		{
			auths[i] = new SimpleGrantedAuthority(authorisations[i]);
		}
		return new AclAuthorizationStrategyImpl(auths);
	}

	@Override
	public Class<?> getObjectType() {
		return AclAuthorizationStrategyImpl.class;
	}

	@Override
	public boolean isSingleton() {
		return false;
	}

}
