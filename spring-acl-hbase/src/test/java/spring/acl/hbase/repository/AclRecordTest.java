package spring.acl.hbase.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.NavigableMap;
import java.util.TreeMap;

import org.apache.commons.lang.ArrayUtils;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.ObjectIdentity;

import spring.acl.hbase.identifier.converter.StringAclIdentifierConverter;


public class AclRecordTest {
	private static final String SOME_PRINCIPAL = "Some Principal";
	private static final String ID = "Some id";
	private static final String TYPE = "SomeType";
	
	@Test
	public void creatingKeyFromIdentityWithByteArrayIdentifier(){
		ObjectIdentity identity = new ObjectIdentityImpl(TYPE, ID.getBytes());
		
		AclRecord underTest = new AclRecord(identity, null);
		
		assertEquals(identity, underTest.getIdentity());
		assertTrue(ArrayUtils.isEquals(ID.getBytes(), underTest.getKey()));
		assertTrue(ArrayUtils.isEquals(byte[].class.getName().getBytes(), underTest.getIdTypeBytes()));
	}
	
	@Test
	public void creatingKeyFromIdentityWithConvertableIdentifier(){
		ObjectIdentity identity = new ObjectIdentityImpl(TYPE, ID);
		
		AclRecord underTest = new AclRecord(identity, new StringAclIdentifierConverter());
		
		assertEquals(identity, underTest.getIdentity());
		assertTrue(ArrayUtils.isEquals(ID.getBytes(), underTest.getKey()));
		assertTrue(ArrayUtils.isEquals(String.class.getName().getBytes(), underTest.getIdTypeBytes()));
	}
	
	@Test(expected = AuthorizationServiceException.class)
	public void creatingIdentityBytesWithNoConverter(){
		ObjectIdentity identity = new ObjectIdentityImpl(TYPE, ID);
		new AclRecord(identity, null);
	}
	
	@Test
	public void creatingRecordFromBytesWithPrincipalOwner(){
		NavigableMap<byte[], byte[]> familyMap = recordMap(String.class, true);
		AclRecord underTest = new AclRecord(ID.getBytes(), familyMap, new StringAclIdentifierConverter());
		
		ObjectIdentity identity = new ObjectIdentityImpl(TYPE, ID);
		
		assertEquals(identity, underTest.getIdentity());
		assertTrue(ArrayUtils.isEquals(ID.getBytes(), underTest.getKey()));
		assertTrue(ArrayUtils.isEquals(String.class.getName().getBytes(), underTest.getIdTypeBytes()));
		assertEquals(new PrincipalSid(SOME_PRINCIPAL), underTest.getOwner());
	}
	
	@Test
	public void creatingRecordFromBytesWithNonPrincipalOwner(){
		NavigableMap<byte[], byte[]> familyMap = recordMap(String.class, false);
		AclRecord underTest = new AclRecord(ID.getBytes(), familyMap, new StringAclIdentifierConverter());
		
		ObjectIdentity identity = new ObjectIdentityImpl(TYPE, ID);
		
		assertEquals(identity, underTest.getIdentity());
		assertTrue(ArrayUtils.isEquals(ID.getBytes(), underTest.getKey()));
		assertTrue(ArrayUtils.isEquals(String.class.getName().getBytes(), underTest.getIdTypeBytes()));
		assertEquals(new GrantedAuthoritySid(SOME_PRINCIPAL), underTest.getOwner());
	}
	
	@Test
	public void creatingIdentityWithByteArrayIdentifier(){
		NavigableMap<byte[], byte[]> familyMap = recordMap(byte[].class, false);
		AclRecord underTest = new AclRecord(ID.getBytes(), familyMap, null);
		
		ObjectIdentity returnedIdentity = underTest.getIdentity();
		assertEquals(TYPE, returnedIdentity.getType());
		assertTrue(ArrayUtils.isEquals(ID.getBytes(), returnedIdentity.getIdentifier()));
		assertTrue(ArrayUtils.isEquals(ID.getBytes(), underTest.getKey()));
		assertTrue(ArrayUtils.isEquals(byte[].class.getName().getBytes(), underTest.getIdTypeBytes()));
		assertEquals(new GrantedAuthoritySid(SOME_PRINCIPAL), underTest.getOwner());
	}
	
	@Test(expected = AuthorizationServiceException.class)
	public void creatingNonSerializableIdentityThrowsException(){
		NavigableMap<byte[], byte[]> recordMap = recordMap(Object.class, false);
		new AclRecord(ID.getBytes(), recordMap, null);
	}
	
	@Test(expected = AuthorizationServiceException.class)
	public void creatingIdentityWithNoConverter(){
		NavigableMap<byte[], byte[]> recordMap = recordMap(String.class, false);
		new AclRecord(ID.getBytes(), recordMap, null);
	}
	
	private NavigableMap<byte[], byte[]> recordMap(final Class<?> idType, final boolean principal){
		String ownerString = SOME_PRINCIPAL+":"+principal;
		
		NavigableMap<byte[], byte[]> recordMap = new TreeMap<byte[], byte[]>(Bytes.BYTES_COMPARATOR);
		recordMap.put(HBaseACLRepository.ACL_ID_TYPE_QUALIFIER, idType.getName().getBytes());
		recordMap.put(HBaseACLRepository.ACL_TYPE_QUALIFIER, TYPE.getBytes());
		recordMap.put(HBaseACLRepository.ACL_OWNER_QUALIFIER, ownerString.getBytes());
		return recordMap;
	}
	
}
