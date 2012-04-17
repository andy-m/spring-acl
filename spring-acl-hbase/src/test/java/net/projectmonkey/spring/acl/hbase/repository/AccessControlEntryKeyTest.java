package net.projectmonkey.spring.acl.hbase.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import net.projectmonkey.spring.acl.hbase.repository.AccessControlEntryKey;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;

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

public class AccessControlEntryKeyTest {

	private static final String POSITION_1 = "1";
	private static final byte[] POSITION_1_BYTES = POSITION_1.getBytes();
	
	@Test
	public void constructingKeyFromPositionCreatesTheCorrectByteArray(){
		AccessControlEntryKey underTest = new AccessControlEntryKey(1);
		assertEquals(1, underTest.getPosition());
		assertTrue(ArrayUtils.isEquals(POSITION_1_BYTES, underTest.getKey()));
	}
	
	@Test
	public void keyIsReconstructedFromBytesCorrectly(){
		AccessControlEntryKey underTest = new AccessControlEntryKey(POSITION_1_BYTES);
		assertEquals(1, underTest.getPosition());
		assertEquals(POSITION_1_BYTES, underTest.getKey());
	}
	
}
