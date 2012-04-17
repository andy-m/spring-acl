package net.projectmonkey.spring.acl.hbase.repository;

import java.io.Serializable;
import java.util.Map;

import net.projectmonkey.spring.acl.hbase.identifier.converter.AclIdentifierConverter;
import net.projectmonkey.spring.acl.util.SidUtil;
import net.projectmonkey.spring.acl.util.generics.GenericTypeResolver;

import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.ObjectIdentity;
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

/**
 * Represents details we need to persist about an Acl
 * excluding its contained {@link AccessControlEntry}'s.
 * 
 * The key of an acl row is a byte[] representation of the 
 * {@link Serializable} identifier supplied in the {@link ObjectIdentity}
 * 
 * Several values are also stored in an 'acl' family - these include
 * the class of the supplied {@link Serializable} identifier, the
 * class of the secured object and a String representing the owner in
 * the form: authority:principal(true/false). 
 * 
 * @author Andy Moody
 */
public class AclRecord {

	private static final String SEPARATOR = ":";

	private final ObjectIdentity identity;
	private final byte[] key;
	private final Sid owner;
	
	/**
	 * Minimal constructor for when we don't care about anything except the ObjectIdentity
	 * e.g. for acl retrieval
	 * 
	 * The converter is required for all identifier types except byte[] although several key types are already
	 * catered for via the default converters in {@link HBaseACLRepository}
	 * 
	 * N.B. The converter is required to be configured with a class exactly matching the stored id type
	 * 
	 * To configure the converter see {@link HBaseACLRepository}.
	 * 
	 * @param identity
	 * @param converter
	 */
	public AclRecord(final ObjectIdentity identity, final AclIdentifierConverter<?> converter) {
		this(identity, null, converter);
	}

	/**
	 * Complete constructor for when we want to construct the acl with all details we need to persist.
	 * 
	 * The converter is required for all identifier types except byte[] although several key types are already
	 * catered for via the default converters in {@link HBaseACLRepository}
	 * 
	 * N.B. The converter is required to be configured with a class exactly matching the stored id type
	 * 
	 * To configure the converter see {@link HBaseACLRepository}.
	 * 
	 * @param identity
	 * @param converter
	 */
	public AclRecord(final ObjectIdentity identity, final Sid owner, final AclIdentifierConverter<?> converter) {
		this.identity = identity;
		this.key = createKey(identity.getIdentifier(), converter);
		this.owner = owner;
	}

	/**
	 * Constructor used to reconstruct the record object when retrieving the acl from the HBase table.
	 * The key is a byte array representing the byte[] version of the {@link Serializable} identifier.
	 * The aclValuesByQualifier map is the family map for the 'acl' family as returned by Hbase
	 * and contains other vital information as described above.
	 * 
	 * The converter is required for all key types except byte[] although several key types are already
	 * catered for via the default converters in {@link HBaseACLRepository}
	 * 
	 * N.B. The converter is required to be configured with a class exactly matching the stored id type 
	 * 
	 * To configure the converter see {@link HBaseACLRepository}.
	 * 
	 * @param key
	 * @param aclValuesByQualifier
	 * @param converter
	 */
	public AclRecord(final byte[] key, final Map<byte[], byte[]> aclValuesByQualifier, final AclIdentifierConverter<?> converter) {
		byte[] idTypeBytes = aclValuesByQualifier.get(HBaseACLRepository.ACL_ID_TYPE_QUALIFIER);
		byte[] typeBytes = aclValuesByQualifier.get(HBaseACLRepository.ACL_TYPE_QUALIFIER);
		byte[] ownerBytes = aclValuesByQualifier.get(HBaseACLRepository.ACL_OWNER_QUALIFIER);
		Serializable identifier = createId(key, idTypeBytes, converter);
		String type = new String(typeBytes);
		this.key = key;
		this.owner = createOwner(ownerBytes);
		this.identity = new ObjectIdentityImpl(type, identifier);
	}

	public byte[] getTypeBytes() {
		return getType().getBytes();
	}

	public byte[] getIdTypeBytes() {
		return getId().getClass().getName().getBytes();
	}

	public ObjectIdentity getIdentity() {
		return identity;
	}

	public byte[] getKey() {
		return key;
	}
	
	public Sid getOwner() {
		return owner;
	}
	
	public byte[] getOwnerBytes() {
		String authority = SidUtil.resolveAuthority(owner);
		StringBuilder builder = new StringBuilder(authority);
		builder.append(SEPARATOR);
		builder.append(SidUtil.isPrincipal(owner));
		return builder.toString().getBytes();
	}
	
	private Serializable createId(final byte[] idBytes, final byte[] idTypeBytes, final AclIdentifierConverter<?> converter) {
		Class<?> idClass = resolveClass(idTypeBytes);
		if(!Serializable.class.isAssignableFrom(idClass)){
			throw new AuthorizationServiceException(idClass+" does not implement Serializable");
		}
		Serializable identifier = null;
		if(byte[].class.equals(idClass))
		{
			identifier = idBytes;
		}
		else if(converter != null)
		{
			verifyConverterType(converter, idClass);
			try
			{
				identifier = converter.fromByteArray(idBytes);
			}
			catch(Exception e)
			{
				throw new AuthorizationServiceException("An exception occurred instantiating "+idClass+" from id bytes", e);
			}
		}
		else
		{
			throw new AuthorizationServiceException("No converter configured for identifier class "+idClass);
		}
		if(identifier == null){
			throw new AuthorizationServiceException("Null identifier returned for byte[] "+idBytes+" and converter "+converter);
		}
		return identifier;
	}

	private void verifyConverterType(final AclIdentifierConverter<?> converter, final Class<?> idClass) {
		Class<?> convertableType = GenericTypeResolver.getFirstGenericTypeFrom(converter, AclIdentifierConverter.class);
		if(!idClass.equals(convertableType)){
			throw new AuthorizationServiceException("Converter "+converter+" is not appropriate for "+idClass);
		}
	}

	private Class<?> resolveClass(final byte[] idTypeBytes) {
		String idString = new String(idTypeBytes);
		try
		{
			return Class.forName(idString);
		}
		catch (ClassNotFoundException e)
		{
			throw new AuthorizationServiceException("Unable to find class "+idString, e);
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private byte[] createKey(final Serializable identifier, final AclIdentifierConverter converter) {
		byte[] toReturn;
		if(identifier instanceof byte[])
		{
			toReturn = (byte[]) identifier;
		}
		else if(converter != null)
		{
			verifyConverterType(converter, identifier.getClass());
			try
			{
				toReturn = converter.toByteArray(identifier);
			}
			catch (Exception e)
			{
				throw new AuthorizationServiceException("An unexpected exception occurred converting from "+identifier+" to byte[] using converter "+converter, e);
			}
		}
		else
		{
			throw new AuthorizationServiceException("No converter configured for identifier type "+identifier.getClass());
		}
		if (toReturn == null)
		{
			throw new AuthorizationServiceException("Null key returned for " + identifier + " and converter "
					+ converter);
		}
		return toReturn;
	}
	
	private Sid createOwner(final byte[] ownerBytes) {
		String ownerString = new String(ownerBytes);
		String[] ownerComponents = ownerString.split(":");
		boolean principal = Boolean.valueOf(ownerComponents[1]);
		return SidUtil.createSid(ownerComponents[0], principal);
	}

	private String getType() {
		return identity.getType();
	}
	
	private Serializable getId() {
		return identity.getIdentifier();
	}

}