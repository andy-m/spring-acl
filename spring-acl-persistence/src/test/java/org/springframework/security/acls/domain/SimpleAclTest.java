package org.springframework.security.acls.domain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.acls.domain.BasePermission.ADMINISTRATION;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.UnloadedSidException;

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

public class SimpleAclTest {
	
	private SimpleAcl underTest;
	@Mock
	private ObjectIdentity identity;
	@Mock
	private Sid owner;
	@Mock
	private AccessControlEntryImpl entry;
	@Mock
	private Sid someSid;
	@Mock
	private ACLUtil util;
	private List<AccessControlEntry> entries;
	private List<Sid> loadedSids;
	
	@Before
	public void setUp(){
		MockitoAnnotations.initMocks(this);
		entries = new ArrayList<AccessControlEntry>();
		entries.add(entry);
		loadedSids = new ArrayList<Sid>();
		loadedSids.add(someSid);
		underTest = new SimpleAcl(identity, owner, entries, loadedSids, util);
	}
	
	@Test
	public void entriesListIsModifiableButDoesNotAffectTheStoredCopyWhenReturned(){
		List<AccessControlEntry> returned = underTest.getEntries();
		assertEquals(entries, returned);
		AccessControlEntry newEntry = Mockito.mock(AccessControlEntry.class);
		returned.add(newEntry);
		assertTrue(returned.contains(newEntry));
		assertFalse(entries.contains(newEntry));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void isGrantedWhenNoPermissionsProvided(){
		underTest.isGranted(new ArrayList<Permission>(), Arrays.asList(owner), false);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void isGrantedWhenNoSidsProvided(){
		underTest.isGranted(Arrays.asList(BasePermission.CREATE), new ArrayList<Sid>(), false);
	}
	
	@Test(expected = UnloadedSidException.class)
	public void isGrantedWhenAnyOfTheRequestedSidsAreLoaded(){
		underTest.isGranted(Arrays.asList(BasePermission.CREATE), Arrays.asList(someSid, owner), false);
	}
	
	@Test
	public void isGrantedWhenAllSidsAreLoaded(){
		List<Permission> permissions = Arrays.asList(BasePermission.CREATE);
		List<Sid> sids = Arrays.asList(someSid);
		Mockito.when(util.isGranted(underTest, permissions, sids, false)).thenReturn(true);
		
		boolean granted = underTest.isGranted(permissions, sids, false);
		
		assertTrue(granted);
	}
	
	@Test
	public void isSidLoadedReturnsTrueIfAllRequestedSidsAreLoaded(){
		boolean returned = underTest.isSidLoaded(Arrays.asList(someSid));
		assertTrue(returned);
	}
	
	@Test
	public void isSidLoadedReturnsFalseIfAnySidsAreNotLoaded(){
		boolean returned = underTest.isSidLoaded(Arrays.asList(someSid, owner));
		assertFalse(returned);
	}
	
	@Test
	public void isSidLoadedReturnsTrueIfLoadedSidsIsNull(){
		underTest = new SimpleAcl(identity, owner, entries, null, util);
		boolean returned = underTest.isSidLoaded(Arrays.asList(someSid, owner));
		assertTrue(returned);
	}
	
	@Test
	public void isSidLoadedReturnsTrueIfNullSidsAreRequested(){
		boolean returned = underTest.isSidLoaded(null);
		assertTrue(returned);
	}
	
	@Test
	public void isSidLoadedReturnsTrueIfNoSidsAreRequested(){
		boolean returned = underTest.isSidLoaded(new ArrayList<Sid>());
		assertTrue(returned);
	}
	
	@Test(expected=NotFoundException.class)
	public void updateAceWhenRequestedIndexIsLessThanZero(){
		underTest.updateAce(-1, ADMINISTRATION);
	}
	
	@Test(expected=NotFoundException.class)
	public void updateAceWhenRequestedIndexIsEqualToTheNumberOfEntries(){
		underTest.updateAce(1, ADMINISTRATION);
	}
	
	@Test(expected=NotFoundException.class)
	public void updateAceWhenRequestedIndexIsGreaterThanTheNumberOfEntries(){
		underTest.updateAce(2, ADMINISTRATION);
	}
	
	@Test
	public void updateAce(){
		underTest.updateAce(0, ADMINISTRATION);
		Mockito.verify(entry).setPermission(ADMINISTRATION);
	}

	@Test(expected=NotFoundException.class)
	public void deleteAceWhenRequestedIndexIsLessThanZero(){
		underTest.deleteAce(-1);
	}
	
	@Test(expected=NotFoundException.class)
	public void deleteAceWhenRequestedIndexIsEqualToTheNumberOfEntries(){
		underTest.deleteAce(1);
	}
	
	@Test(expected=NotFoundException.class)
	public void deleteAceWhenRequestedIndexIsGreaterThanTheNumberOfEntries(){
		underTest.deleteAce(2);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void insertAceWithNoPermission(){
		underTest.insertAce(0, null, someSid, true);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void insertAceWithNoSid(){
		underTest.insertAce(0, ADMINISTRATION, null, true);
	}
	
	@Test(expected=AccessDeniedException.class)
	public void insertAceWithoutTheAppropriateAuthorization(){
		Mockito.doThrow(new AccessDeniedException("")).when(util).securityCheck(underTest, AclAuthorizationStrategy.CHANGE_GENERAL);
		underTest.insertAce(0, ADMINISTRATION, someSid, true);
	}
	
	@Test(expected=NotFoundException.class)
	public void insertAceWhenRequestedIndexIsLessThanZero(){
		underTest.insertAce(-1, ADMINISTRATION, someSid, true);
	}
	
	@Test(expected=NotFoundException.class)
	public void insertAceWhenRequestedIndexIsGreaterThanTheNumberOfEntries(){
		underTest.insertAce(2, ADMINISTRATION, someSid, true);
	}
	
	@Test
	public void insertAceWhenRequestedIndexIsEqualToTheNumberOfEntries(){
		underTest.insertAce(1, ADMINISTRATION, someSid, true);
		
		assertEquals(2, entries.size());
		assertCreatedEntry(entries.get(1));
	}
	
	@Test
	public void insertAceWhenRequestedIndexIsLessThanTheNumberOfEntries(){
		underTest.insertAce(0, ADMINISTRATION, someSid, true);
		
		assertEquals(2, entries.size());
		assertCreatedEntry(entries.get(0));
	}

	private void assertCreatedEntry(final AccessControlEntry newEntry) {
		assertEquals(someSid, newEntry.getSid());
		assertEquals(underTest, newEntry.getAcl());
		assertEquals(ADMINISTRATION, newEntry.getPermission());
	}
	
	@Test
	public void deleteAce(){
		underTest.deleteAce(0);
		assertTrue(entries.isEmpty());
	}

}
