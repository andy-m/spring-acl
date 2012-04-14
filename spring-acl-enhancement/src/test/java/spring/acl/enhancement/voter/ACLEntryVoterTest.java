package spring.acl.enhancement.voter;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_ABSTAIN;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_DENIED;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_GRANTED;

import java.util.Collection;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;


import spring.acl.enhancement.identity.strategy.method.MethodInvocationObjectIdRetrievalStrategy;
import spring.acl.enhancement.voter.AclEntryVoter;



public class ACLEntryVoterTest {

	private static final String PROCESS_CONFIG_ATTRIBUTE = "SOME_ATTRIBUTE";
	
	@Mock
	private AclService aclService;
	@Mock
	private MethodInvocationObjectIdRetrievalStrategy objectIdentityRetrievalStrategy;
	@Mock
	private SidRetrievalStrategy sidRetrievalStrategy;
	@Mock
	private Permission permission1;
	@Mock
	private Permission permission2;
	@Mock
	private Authentication authentication;
	@Mock
	private ConfigAttribute attribute;
	@Mock
	private MethodInvocation invocation;
	@Mock
	private ObjectIdentity identity;
	@Mock
	private Sid sid;
	@Mock
	private Acl acl;
	
	private List<Permission> permissions;
	private Collection<ConfigAttribute> attributes;
	private List<Sid> sids;
	private AclEntryVoter underTest;

	
	@Before
	public void setUp(){
		initMocks(this);
		permissions = asList(permission1, permission2);
		attributes = asList(attribute);
		sids = asList(sid);
		underTest = new AclEntryVoter(aclService, PROCESS_CONFIG_ATTRIBUTE, permissions, objectIdentityRetrievalStrategy, sidRetrievalStrategy);
	}
	
	@Test
	public void abstainsIfNoConfigAttributesMatch(){
		when(attribute.getAttribute()).thenReturn(PROCESS_CONFIG_ATTRIBUTE + 1);
		int returned = underTest.vote(authentication, invocation, attributes);
		assertEquals(ACCESS_ABSTAIN, returned);
	}
	
	@Test
	public void abstainsIfConfigAttributesMatchButNoIdentityIsLocated(){
		when(attribute.getAttribute()).thenReturn(PROCESS_CONFIG_ATTRIBUTE);
		when(objectIdentityRetrievalStrategy.getObjectIdentity(invocation)).thenReturn(null);
		int returned = underTest.vote(authentication, invocation, attributes);
		assertEquals(ACCESS_ABSTAIN, returned);
	}
	
	@Test
	public void deniesAccessIfACLNotFoundForObjectIdentityAndSIDs(){
		when(attribute.getAttribute()).thenReturn(PROCESS_CONFIG_ATTRIBUTE);
		when(objectIdentityRetrievalStrategy.getObjectIdentity(invocation)).thenReturn(identity);
		when(sidRetrievalStrategy.getSids(authentication)).thenReturn(sids);
		when(aclService.readAclById(identity, sids)).thenThrow(new NotFoundException(""));
		int returned = underTest.vote(authentication, invocation, attributes);
		assertEquals(ACCESS_DENIED, returned);
	}
	
	@Test
	public void deniesAccessIfPermissionsNotGrantedForACL(){
		when(attribute.getAttribute()).thenReturn(PROCESS_CONFIG_ATTRIBUTE);
		when(objectIdentityRetrievalStrategy.getObjectIdentity(invocation)).thenReturn(identity);
		when(sidRetrievalStrategy.getSids(authentication)).thenReturn(sids);
		when(aclService.readAclById(identity, sids)).thenReturn(acl);
		when(acl.isGranted(permissions, sids, false)).thenReturn(false);
		int returned = underTest.vote(authentication, invocation, attributes);
		assertEquals(ACCESS_DENIED, returned);
	}
	
	@Test
	public void deniesAccessIfPermissionsNotFoundInAcl(){
		when(attribute.getAttribute()).thenReturn(PROCESS_CONFIG_ATTRIBUTE);
		when(objectIdentityRetrievalStrategy.getObjectIdentity(invocation)).thenReturn(identity);
		when(sidRetrievalStrategy.getSids(authentication)).thenReturn(sids);
		when(aclService.readAclById(identity, sids)).thenReturn(acl);
		when(acl.isGranted(permissions, sids, false)).thenThrow(new NotFoundException(""));
		int returned = underTest.vote(authentication, invocation, attributes);
		assertEquals(ACCESS_DENIED, returned);
	}
	
	@Test
	public void grantsAccessIfPermissionsGrantedInAcl(){
		when(attribute.getAttribute()).thenReturn(PROCESS_CONFIG_ATTRIBUTE);
		when(objectIdentityRetrievalStrategy.getObjectIdentity(invocation)).thenReturn(identity);
		when(sidRetrievalStrategy.getSids(authentication)).thenReturn(sids);
		when(aclService.readAclById(identity, sids)).thenReturn(acl);
		when(acl.isGranted(permissions, sids, false)).thenReturn(true);
		int returned = underTest.vote(authentication, invocation, attributes);
		assertEquals(ACCESS_GRANTED, returned);
	}

}
