package spring.acl.service;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;

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
	private MutableAcl acl;

	@Before
	public void setUp() {
		MockitoAnnotations.initMocks(this);
		underTest = new SimpleACLService(repository);
	}

	@Test(expected = AlreadyExistsException.class)
	public void createAclWhenIdAlreadyExists() {
		Mockito.when(repository.create(oid)).thenThrow(new AlreadyExistsException(""));
		underTest.createAcl(oid);
	}

	@Test
	public void createAclWhenIdDoesNotAlreadyExist() {
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
	public void updateAcl(){
		underTest.updateAcl(acl);
		Mockito.verify(repository).update(acl);
	}
	
}
