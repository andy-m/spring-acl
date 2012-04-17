package spring.acl.service;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

import spring.acl.entity.SimpleMutableAcl;
import spring.acl.repository.ACLUpdateRepository;

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

public class SimpleACLServiceTest {

	private SimpleACLService underTest;
	@Mock
	private ACLUpdateRepository repository;
	@Mock
	private ObjectIdentity oid;
	@Mock
	private SimpleMutableAcl acl;
	@Mock
	private Sid sid;

	@Before
	public void setUp() {
		MockitoAnnotations.initMocks(this);
		underTest = new SimpleACLService(repository);
	}

	@Test(expected = AlreadyExistsException.class)
	public void createAclWhenIdAlreadyExists() {
		Mockito.when(repository.isThereAnAclFor(oid)).thenReturn(true);
		underTest.createAcl(oid);
		Mockito.verifyNoMoreInteractions(repository);
	}

	@Test
	public void createAclWhenIdDoesNotAlreadyExist() {
		Mockito.when(repository.isThereAnAclFor(oid)).thenReturn(false);
		Mockito.when(repository.create(oid)).thenReturn(acl);
		
		MutableAcl returned = underTest.createAcl(oid);
		
		assertEquals(acl, returned);
	}
	
	@Test
	public void deleteAcl(){
		underTest.deleteAcl(oid, true);
		Mockito.verify(repository).delete(oid);
	}
	
	@Test
	public void updateAclWhenAclExists(){
		Mockito.when(acl.getObjectIdentity()).thenReturn(oid);
		Mockito.when(repository.isThereAnAclFor(oid)).thenReturn(true);
		underTest.updateAcl(acl);
		Mockito.verify(repository).update(acl);
	}
	
	@Test(expected = NotFoundException.class)
	public void updateAclWhenAclDoesNotExist(){
		Mockito.when(acl.getObjectIdentity()).thenReturn(oid);
		Mockito.when(repository.isThereAnAclFor(oid)).thenReturn(false);
		underTest.updateAcl(acl);
		Mockito.verifyNoMoreInteractions(repository);
	}
	
	@Test
	public void readAclById(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		values.put(oid, acl);
		Mockito.when(repository.getAclsById(oids, null)).thenReturn(values);
		Acl returned = underTest.readAclById(oid);
		assertEquals(acl, returned);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void readAclByIdWhenIdIsNull(){
		underTest.readAclById(null);
	}
	
	@Test(expected = NotFoundException.class)
	public void readAclByIdWhenAclNotFound(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		Mockito.when(repository.getAclsById(oids, null)).thenReturn(values);
		underTest.readAclById(oid);
	}
	
	@Test
	public void readAclByIdAndSids(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		List<Sid> sids = Arrays.asList(sid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		values.put(oid, acl);
		Mockito.when(repository.getAclsById(oids, sids)).thenReturn(values);
		Acl returned = underTest.readAclById(oid, sids);
		assertEquals(acl, returned);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void readAclByIdAndSidsWhenIdIsNull(){
		List<Sid> sids = Arrays.asList(sid);
		underTest.readAclById(null, sids);
	}
	
	@Test(expected = NotFoundException.class)
	public void readAclByIdAndSidsWhenAclNotFound(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		List<Sid> sids = Arrays.asList(sid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		Mockito.when(repository.getAclsById(oids, sids)).thenReturn(values);
		underTest.readAclById(oid, sids);
	}
	
	@Test
	public void readAclsById(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		values.put(oid, acl);
		Mockito.when(repository.getAclsById(oids, null)).thenReturn(values);
		Map<ObjectIdentity, Acl> returned = underTest.readAclsById(oids);
		assertEquals(values, returned);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void readAclsByIdWhenIdIsNull(){
		underTest.readAclsById(Arrays.asList(oid, null));
	}
	
	@Test(expected = NotFoundException.class)
	public void readAclsByIdWhenAclNotFound(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		Mockito.when(repository.getAclsById(oids, null)).thenReturn(values);
		underTest.readAclsById(oids);
	}
	
	@Test
	public void readAclsByIdAndSids(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		List<Sid> sids = Arrays.asList(sid);
		
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		values.put(oid, acl);
		Mockito.when(repository.getAclsById(oids, sids)).thenReturn(values);
		Map<ObjectIdentity, Acl> returned = underTest.readAclsById(oids, sids);
		assertEquals(values, returned);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void readAclsByIdAndSidsWhenIdIsNull(){
		List<Sid> sids = Arrays.asList(sid);
		underTest.readAclsById(Arrays.asList(oid, null), sids);
	}
	
	@Test(expected = NotFoundException.class)
	public void readAclsByIdAndSidsWhenAclNotFound(){
		List<ObjectIdentity> oids = Arrays.asList(oid);
		List<Sid> sids = Arrays.asList(sid);
		Map<ObjectIdentity, Acl> values = new HashMap<ObjectIdentity, Acl>();
		Mockito.when(repository.getAclsById(oids, sids)).thenReturn(values);
		underTest.readAclsById(oids);
	}
	
	
}
