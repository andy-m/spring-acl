package spring.acl.hbase.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;

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
