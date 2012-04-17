package spring.acl.factory;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import spring.acl.factory.DefaultAclAuthorizationStrategyFactoryBean;
import spring.acl.util.reflect.FieldUtil;

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
 * @author Andy Moody
 */
public class DefaultAclAuthorizationStrategyFactoryBeanTest {
	
	
	private static final String AUTHORITY_1 = "auth1";
	private static final String AUTHORITY_2 = "auth2";
	private static final String AUTHORITY_3 = "auth3";

	@Test(expected=IllegalArgumentException.class)
	public void creatingObjectWithNoSuppliedAuthorities(){
		new DefaultAclAuthorizationStrategyFactoryBean();
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void creatingObjectWithTheWrongNumberOfAuthorities(){
		new DefaultAclAuthorizationStrategyFactoryBean(AUTHORITY_1, AUTHORITY_2);
	}
	
	@Test
	public void creatingObjectWith1Authority() throws Exception{
		DefaultAclAuthorizationStrategyFactoryBean underTest = new DefaultAclAuthorizationStrategyFactoryBean(AUTHORITY_1);
		AclAuthorizationStrategyImpl returned = underTest.getObject();
		
		SimpleGrantedAuthority expected = new SimpleGrantedAuthority(AUTHORITY_1);
		
		assertEquals(expected, FieldUtil.getFieldValue(returned, "gaTakeOwnership"));
		assertEquals(expected, FieldUtil.getFieldValue(returned, "gaModifyAuditing"));
		assertEquals(expected, FieldUtil.getFieldValue(returned, "gaGeneralChanges"));
	}
	
	@Test
	public void creatingObjectWith3Authorities() throws Exception{
		DefaultAclAuthorizationStrategyFactoryBean underTest = new DefaultAclAuthorizationStrategyFactoryBean(AUTHORITY_1, AUTHORITY_2, AUTHORITY_3);
		AclAuthorizationStrategyImpl returned = underTest.getObject();
		
		SimpleGrantedAuthority expected1 = new SimpleGrantedAuthority(AUTHORITY_1);
		SimpleGrantedAuthority expected2 = new SimpleGrantedAuthority(AUTHORITY_2);
		SimpleGrantedAuthority expected3 = new SimpleGrantedAuthority(AUTHORITY_3);
		
		assertEquals(expected1, FieldUtil.getFieldValue(returned, "gaTakeOwnership"));
		assertEquals(expected2, FieldUtil.getFieldValue(returned, "gaModifyAuditing"));
		assertEquals(expected3, FieldUtil.getFieldValue(returned, "gaGeneralChanges"));
	}

}
