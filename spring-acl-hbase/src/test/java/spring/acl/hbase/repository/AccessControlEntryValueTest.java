package spring.acl.hbase.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.UUID;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;

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

public class AccessControlEntryValueTest {
	
	private static final Permission PERMISSION = BasePermission.CREATE;
	private static final String AUTHORITY = "Authority";
	private static final UUID ID = UUID.randomUUID();
	private static final String ID_STRING = ID.toString();
	private static final String GRANTING_PRINCIPAL_KEY = ID_STRING+":"+AUTHORITY+":true:"+PERMISSION.getMask()+":true";
	private static final String GRANTING_NON_PRINCIPAL_KEY = ID_STRING+":"+AUTHORITY+":false:"+PERMISSION.getMask()+":true";
	private static final String DENYING_PRINCIPAL_KEY = ID_STRING+":"+AUTHORITY+":true:"+PERMISSION.getMask()+":false";
	private static final String DENYING_NON_PRINCIPAL_KEY = ID_STRING+":"+AUTHORITY+":false:"+PERMISSION.getMask()+":false";
	private static final byte[] GRANTING_PRINCIPAL_KEY_BYTES = GRANTING_PRINCIPAL_KEY.getBytes();
	private static final byte[] GRANTING_NON_PRINCIPAL_KEY_BYTES = GRANTING_NON_PRINCIPAL_KEY.getBytes();
	private static final byte[] DENYING_PRINCIPAL_KEY_BYTES = DENYING_PRINCIPAL_KEY.getBytes();
	private static final byte[] DENYING_NON_PRINCIPAL_KEY_BYTES = DENYING_NON_PRINCIPAL_KEY.getBytes();
	@Mock
	private PermissionFactory permissionFactory;
	

	@Before
	public void setUp(){
		MockitoAnnotations.initMocks(this);
	}
	
	@Test
	public void keyCreatedCorrectlyForGrantingPermissionAndPrincipal(){
		Sid sid = new PrincipalSid(AUTHORITY);
		AccessControlEntryValue underTest = new AccessControlEntryValue(ID, sid, PERMISSION, true);
		assertTrue(underTest.isGranting());
		assertTrue(ArrayUtils.isEquals(GRANTING_PRINCIPAL_KEY_BYTES, underTest.getKey()));
		assertEquals(ID, underTest.getId());
		assertEquals(sid, underTest.getSid());
		assertEquals(AUTHORITY, underTest.getAuthority());
		assertEquals(PERMISSION, underTest.getPermission());
	}
	
	@Test
	public void keyCreatedCorrectlyForGrantingPermissionAndNONPrincipal(){
		Sid sid = new GrantedAuthoritySid(AUTHORITY);
		AccessControlEntryValue underTest = new AccessControlEntryValue(ID, sid, PERMISSION, true);
		assertTrue(underTest.isGranting());
		assertTrue(ArrayUtils.isEquals(GRANTING_NON_PRINCIPAL_KEY_BYTES, underTest.getKey()));
		assertEquals(ID, underTest.getId());
		assertEquals(sid, underTest.getSid());
		assertEquals(AUTHORITY, underTest.getAuthority());
		assertEquals(PERMISSION, underTest.getPermission());
	}
	
	@Test
	public void keyCreatedCorrectlyForDenyingPermissionAndPrincipal(){
		Sid sid = new PrincipalSid(AUTHORITY);
		AccessControlEntryValue underTest = new AccessControlEntryValue(ID, sid, PERMISSION, false);
		assertFalse(underTest.isGranting());
		assertTrue(ArrayUtils.isEquals(DENYING_PRINCIPAL_KEY_BYTES, underTest.getKey()));
		assertEquals(ID, underTest.getId());
		assertEquals(sid, underTest.getSid());
		assertEquals(AUTHORITY, underTest.getAuthority());
		assertEquals(PERMISSION, underTest.getPermission());
	}
	
	@Test
	public void keyCreatedCorrectlyForDenyingPermissionAndNonPrincipal(){
		Sid sid = new GrantedAuthoritySid(AUTHORITY);
		AccessControlEntryValue underTest = new AccessControlEntryValue(ID, sid, PERMISSION, false);
		assertFalse(underTest.isGranting());
		assertTrue(ArrayUtils.isEquals(DENYING_NON_PRINCIPAL_KEY_BYTES, underTest.getKey()));
		assertEquals(ID, underTest.getId());
		assertEquals(sid, underTest.getSid());
		assertEquals(AUTHORITY, underTest.getAuthority());
		assertEquals(PERMISSION, underTest.getPermission());
	}
	
	@Test
	public void regeneratingKeyFromDenyingBytes(){
		Mockito.when(permissionFactory.buildFromMask(PERMISSION.getMask())).thenReturn(PERMISSION);
		Sid sid = new GrantedAuthoritySid(AUTHORITY);
		AccessControlEntryValue underTest = new AccessControlEntryValue(DENYING_NON_PRINCIPAL_KEY_BYTES, permissionFactory);
		assertFalse(underTest.isGranting());
		assertTrue(ArrayUtils.isEquals(DENYING_NON_PRINCIPAL_KEY_BYTES, underTest.getKey()));
		assertEquals(ID, underTest.getId());
		assertEquals(sid, underTest.getSid());
		assertEquals(AUTHORITY, underTest.getAuthority());
		assertEquals(PERMISSION, underTest.getPermission());
	}
	
	@Test
	public void regeneratingKeyFromGrantingBytes(){
		Mockito.when(permissionFactory.buildFromMask(PERMISSION.getMask())).thenReturn(PERMISSION);
		Sid sid = new PrincipalSid(AUTHORITY);
		AccessControlEntryValue underTest = new AccessControlEntryValue(GRANTING_PRINCIPAL_KEY_BYTES, permissionFactory);
		assertTrue(underTest.isGranting());
		assertTrue(ArrayUtils.isEquals(GRANTING_PRINCIPAL_KEY_BYTES, underTest.getKey()));
		assertEquals(ID, underTest.getId());
		assertEquals(sid, underTest.getSid());
		assertEquals(AUTHORITY, underTest.getAuthority());
		assertEquals(PERMISSION, underTest.getPermission());
	}
	
}
