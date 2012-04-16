package spring.acl.hbase.repository;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.UUID;

import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.client.HTablePool;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.acls.domain.ACLUtil;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SimpleAcl;
import org.springframework.security.acls.domain.SimpleMutableAcl;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import spring.acl.hbase.identifier.converter.AclIdentifierConverter;
import spring.acl.hbase.identifier.converter.IntegerAclIdentifierConverter;
import spring.acl.hbase.identifier.converter.LongAclIdentifierConverter;
import spring.acl.hbase.identifier.converter.StringAclIdentifierConverter;
import spring.acl.repository.ACLUpdateRepository;
import spring.acl.util.generics.GenericTypeResolver;

import com.google.common.primitives.Primitives;

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
 * HBase repository for {@link Acl} and {@link AccessControlEntry} objects
 * 
 * N.B. This class assumes that the serializable identifier contained within the
 * ObjectIdentity for an Acl is Globally unique. This is because recording the
 * secured class as part of the ACL row key would lead to significantly longer
 * keys (since we'd have to store the fully qualified class name) which is
 * inconsistent with HBase best practice.
 * 
 * The permissionFactory used to recreate permissions can be configured as a property.
 * Similarly you can configure converters for additional identifier types using
 * the supplied setAdditionalConverters method.
 * 
 * @author Andy Moody
 * 
 */
public class HBaseACLRepository implements ACLUpdateRepository {

	static final byte[] ACL_TABLE = "acls".getBytes();
	static final byte[] ACE_FAMILY = "aces".getBytes();
	static final byte[] ACL_FAMILY = "acl".getBytes();
	static final byte[] ACL_ID_TYPE_QUALIFIER = "id_type".getBytes();
	static final byte[] ACL_TYPE_QUALIFIER = "type".getBytes();
	static final byte[] ACL_OWNER_QUALIFIER = "owner".getBytes();
	static final byte[] ACE_PERMISSION_QUALIFIER = "granting".getBytes();
	static final byte[] ACE_SID_QUALIFIER = "sid".getBytes();

	private final HTablePool tablePool;
	private final AclCache aclCache;
	private final ACLUtil util;

	private PermissionFactory permissionFactory = new DefaultPermissionFactory();

	@SuppressWarnings("rawtypes")
	private final Map<Class, AclIdentifierConverter> aclIdentifierConverters;

	/**
	 * S
	 * @param tablePool
	 * @param authorizationStrategy
	 * @param aclCache
	 */
	public HBaseACLRepository(final HTablePool tablePool, final AclAuthorizationStrategy authorizationStrategy,
			final AclCache aclCache){
		this(tablePool, new ConsoleAuditLogger(), authorizationStrategy, aclCache);
	}
	
	/**
	 * Simplified constructor utilising the defaultPermissionGrantingStrategy
	 * with the provided AuditLogger
	 * @param tablePool
	 * @param auditLogger
	 * @param authorizationStrategy
	 * @param aclCache
	 */
	public HBaseACLRepository(final HTablePool tablePool, final AuditLogger auditLogger,
			final AclAuthorizationStrategy authorizationStrategy, final AclCache aclCache) {
		this(tablePool, authorizationStrategy, new DefaultPermissionGrantingStrategy(auditLogger), aclCache);
	}

	/**
	 * Constructor allowing full customization.
	 * @param tablePool
	 * @param authorizationStrategy
	 * @param permissionGrantingStrategy
	 * @param aclCache
	 */
	public HBaseACLRepository(final HTablePool tablePool, final AclAuthorizationStrategy authorizationStrategy,
			final PermissionGrantingStrategy permissionGrantingStrategy, final AclCache aclCache) {
		this.tablePool = tablePool;
		this.aclCache = aclCache;
		this.util = new ACLUtil(permissionGrantingStrategy, authorizationStrategy);
		this.aclIdentifierConverters = map(defaultConverters());
	}

	/**
	 * Creates an acl.
	 * 
	 * @param id which must not be null.
	 * @throws AlreadyExistsException if an acl already exists for the supplied
	 *             identity
	 * @throws AuthorizationServiceException if an unexpected exception occurred
	 */
	@Override
	public SimpleMutableAcl create(final ObjectIdentity id) {
		Assert.notNull(id, "id must not be null");
		if (isThereAnAclFor(id))
		{
			throw new AlreadyExistsException("Acl already exists for identity " + id
					+ " this implementation requires globally unique identifiers");
		}

		HTableInterface table = tablePool.getTable(ACL_TABLE);
		try
		{
			// Need to retrieve the current principal, in order to know who
			// "owns" this ACL (can be changed later on)
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			PrincipalSid owner = new PrincipalSid(auth);

			SimpleAcl acl = new SimpleAcl(id, owner, new ArrayList<AccessControlEntry>(), null, util);
			ObjectIdentity identity = acl.getObjectIdentity();
			save(acl, table, new AclRecord(identity, owner, resolveConverter(identity)));
			return acl;
		}
		catch (IOException e)
		{
			throw new AuthorizationServiceException("An unexpected exception occurred", e);
		}
		finally
		{
			close(table);
		}
	}

	/**
	 * Deletes an acl.
	 * 
	 * @param id which must not be null.
	 * @throws AuthorizationServiceException if an unexpected exception occurred
	 */
	@Override
	public void delete(final ObjectIdentity id) {
		Assert.notNull(id, "id must not be null");
		HTableInterface table = tablePool.getTable(ACL_TABLE);
		try
		{
			deleteInternal(id, table);
		}
		catch (IOException e)
		{
			throw new AuthorizationServiceException("An unexpected exception occurred", e);
		}
		finally
		{
			close(table);
		}
	}

	/**
	 * Updates an existing acl. This deletes the existing acl and completely
	 * replaces the row with the new acl.
	 * 
	 * @param acl which must not be null.
	 * @throws NotFoundException if no corresponding acl exists
	 *             AuthorizationServiceException if: some mandatory aspect of
	 *             the supplied acl is null or if an unexpected exception
	 *             occurred
	 */
	@Override
	public void update(final MutableAcl acl) {
		Assert.notNull(acl, "acl must not be null");

		HTableInterface table = tablePool.getTable(ACL_TABLE);
		try
		{
			ObjectIdentity identity = acl.getObjectIdentity();
			AclRecord aclRecord = new AclRecord(identity, acl.getOwner(), resolveConverter(identity));
			Get get = new Get(aclRecord.getKey());
			boolean exists = table.exists(get);
			if (!exists)
			{
				throw new NotFoundException("Acl does not exist for object identity " + identity);
			}
			deleteInternal(aclRecord, table);
			save(acl, table, aclRecord);
		}
		catch (IOException e)
		{
			throw new AuthorizationServiceException("An unexpected exception occurred", e);
		}
		finally
		{
			close(table);
		}
	}

	/**
	 * Retrieves a single Acl from the given object Identity.
	 * 
	 * @param identity
	 * @return null if the corresponding acl is not found, the acl otherwise.
	 * @throws AuthorizationServiceException if no zero argument key retrieval
	 *             method returning a byte[] could be located for the identifier
	 *             or the located method returned a null key or an unexpected
	 *             exception occurred.
	 */
	public Acl getAclById(final ObjectIdentity identity) {
		Assert.notNull(identity, "Object Identity required");
		return getAclsById(Arrays.asList(identity), null).get(identity);
	}

	/**
	 * Returns the corresponding ACL's mapped by the relevant ObjectIdentity.
	 * ObjectIdentities.identifier objects are required to implement one of the
	 * configured keyRetrievalMethods.
	 * 
	 * @param objectIdentities which must not be null
	 * @param sids which may be null
	 * @return map of ObjectIdentities against the corresponding ACL objects.
	 * @throws AuthorizationServiceException if no zero argument key retrieval
	 *             method returning a byte[] could be located for an identifier
	 *             or the located method returned a null key or an unexpected
	 *             exception occurred.
	 * 
	 */
	@Override
	public Map<ObjectIdentity, Acl> getAclsById(final List<ObjectIdentity> objectIdentities, final List<Sid> sids) {
		Assert.notNull(objectIdentities, "At least one Object Identity required");
		Assert.isTrue(objectIdentities.size() > 0, "At least one Object Identity required");
		HTableInterface table = tablePool.getTable(ACL_TABLE);
		Map<ObjectIdentity, Acl> toReturn = new HashMap<ObjectIdentity, Acl>();
		try
		{
			Map<Long, ObjectIdentity> identitiesByByteId = new HashMap<Long, ObjectIdentity>();
			List<Get> gets = new ArrayList<Get>();
			for (ObjectIdentity identity : objectIdentities)
			{
				if (!toReturn.containsKey(identity))
				{
					MutableAcl acl = aclCache.getFromCache(identity);
					if (acl != null)
					{
						toReturn.put(identity, acl);
					}
					else
					{
						AclRecord aclKey = new AclRecord(identity, resolveConverter(identity));
						byte[] key = aclKey.getKey();
						Long rowId = createRowId(key);
						if (!identitiesByByteId.containsKey(rowId))
						{
							gets.add(new Get(key));
							identitiesByByteId.put(rowId, identity);
						}
					}
				}
			}

			if (!gets.isEmpty())
			{
				Result[] results = table.get(gets);
				Map<ObjectIdentity, Acl> resultsFromDB = mapResults(sids, identitiesByByteId, results);
				toReturn.putAll(resultsFromDB);
			}
			return toReturn;
		}
		catch (IOException e)
		{
			throw new AuthorizationServiceException("An unexpected exception occurred", e);
		}
		finally
		{
			close(table);
		}
	}

	boolean isThereAnAclFor(final ObjectIdentity identity) {
		Assert.notNull(identity, "Object Identity required");
		HTableInterface table = tablePool.getTable(ACL_TABLE);
		try
		{
			AclRecord aclKey = new AclRecord(identity, resolveConverter(identity));
			Get get = new Get(aclKey.getKey());
			return table.exists(get);
		}
		catch (IOException e)
		{
			throw new AuthorizationServiceException("An unexpected exception occurred", e);
		}
		finally
		{
			close(table);
		}
	}

	private Map<ObjectIdentity, Acl> mapResults(final List<Sid> sids, final Map<Long, ObjectIdentity> identitiesByByteId,
			final Result[] results) {
		Map<ObjectIdentity, Acl> toReturn = new HashMap<ObjectIdentity, Acl>();
		for (Result result : results)
		{
			if (!result.isEmpty())
			{
				byte[] rowKey = result.getRow();

				Long rowId = createRowId(rowKey);
				ObjectIdentity identity = identitiesByByteId.get(rowId);

				NavigableMap<byte[], byte[]> aclFamilyMap = result.getFamilyMap(ACL_FAMILY);

				AclRecord aclRecord = new AclRecord(rowKey, aclFamilyMap, resolveConverter(identity));

				List<AccessControlEntry> entries = new ArrayList<AccessControlEntry>();
				MutableAcl acl = new SimpleAcl(identity, aclRecord.getOwner(), entries, sids, util);

				NavigableMap<byte[], byte[]> aceMap = result.getFamilyMap(ACE_FAMILY);
				for (Entry<byte[], byte[]> keyValue : aceMap.entrySet())
				{
					AccessControlEntryValue value = new AccessControlEntryValue(keyValue.getValue(), permissionFactory);
					AccessControlEntry ace = new AccessControlEntryImpl(value.getId(), acl, value.getSid(),
							value.getPermission(), value.isGranting(), false, false);
					entries.add(ace);
				}
				toReturn.put(identity, acl);
				aclCache.putInCache(acl);
			}
		}
		return toReturn;
	}

	/**
	 * Closes the provided table. This should always be called within a finally
	 * block whenever a table is being used.
	 * 
	 * @param table
	 */
	private void close(final HTableInterface table) {
		try
		{
			table.close();
		}
		catch (IOException e)
		{
			throw new AuthorizationServiceException("Unable to close table " + ACL_TABLE, e);
		}
	}

	private AccessControlEntryValue createAceValue(final AccessControlEntry ace) {
		Serializable aceId = ace.getId();
		// we require the ACE ids to be uuids for ease of serialization /
		// deserialization
		UUID id = (UUID) (aceId != null && aceId instanceof UUID ? aceId : UUID.randomUUID());
		return new AccessControlEntryValue(id, ace.getSid(), ace.getPermission(), ace.isGranting());
	}

	private Put createPut(final Acl acl, final AclRecord record) {
		Put put = new Put(record.getKey());
		put.add(ACL_FAMILY, ACL_ID_TYPE_QUALIFIER, record.getIdTypeBytes());
		put.add(ACL_FAMILY, ACL_TYPE_QUALIFIER, record.getTypeBytes());
		put.add(ACL_FAMILY, ACL_OWNER_QUALIFIER, record.getOwnerBytes());
		List<AccessControlEntry> entries = acl.getEntries();
		int i = 0;
		for (AccessControlEntry ace : entries)
		{
			AccessControlEntryKey aceKey = new AccessControlEntryKey(i);
			AccessControlEntryValue aceValue = createAceValue(ace);
			put.add(ACE_FAMILY, aceKey.getKey(), aceValue.getKey());
			i++;
		}
		return put;
	}

	private Long createRowId(final byte[] rowKey) {
		Long rowId = 0L;
		for (byte b : rowKey)
		{
			rowId = rowId + Byte.valueOf(b).intValue();
		}
		return rowId;
	}

	private void deleteInternal(final ObjectIdentity identity, final HTableInterface table) throws IOException {
		AclRecord record = new AclRecord(identity, resolveConverter(identity));
		deleteInternal(record, table);
	}

	/**
	 * Deletes the acl from the database and evicts it from the cache
	 * 
	 * @param record
	 * @param table
	 * @throws IOException
	 */
	private void deleteInternal(final AclRecord record, final HTableInterface table) throws IOException {
		byte[] rowKey = record.getKey();
		aclCache.evictFromCache(record.getIdentity());
		table.delete(new Delete(rowKey));
	}

	private void save(final MutableAcl acl, final HTableInterface table, final AclRecord aclRecord) throws IOException {
		Put put = createPut(acl, aclRecord);
		table.put(put);
	}

	@SuppressWarnings("rawtypes")
	private static Map<Class, AclIdentifierConverter> map(final List<AclIdentifierConverter<?>> additionalConverters) {
		Map<Class, AclIdentifierConverter> toReturn = new HashMap<Class, AclIdentifierConverter>();
		for (AclIdentifierConverter<?> converter : additionalConverters)
		{
			Class<?> identifierType = GenericTypeResolver.getFirstGenericTypeFrom(converter, AclIdentifierConverter.class);
			toReturn.put(identifierType, converter);
		}
		return toReturn;
	}

	private List<AclIdentifierConverter<?>> defaultConverters() {
		List<AclIdentifierConverter<?>> converters = new ArrayList<AclIdentifierConverter<?>>();
		converters.add(new LongAclIdentifierConverter());
		converters.add(new StringAclIdentifierConverter());
		converters.add(new IntegerAclIdentifierConverter());
		return converters;
	}

	private AclIdentifierConverter<?> resolveConverter(final ObjectIdentity identity) {
		Serializable identifier = identity.getIdentifier();
		Assert.notNull(identifier, "Identifier must not be null");
		Class<? extends Serializable> identifierClass = Primitives.wrap(identifier.getClass());
		return aclIdentifierConverters.get(identifierClass);
	}

	
	/* Optional configuration methods */
	/**
	 * Set additional converters. Note, any converters supplied here will override the default converters
	 * if they convert the same type.
	 * @param additionalConverters
	 */
	public void setAdditionalConverters(final List<AclIdentifierConverter<?>> additionalConverters) {
		this.aclIdentifierConverters.putAll(map(additionalConverters));
	}
	
	/**
	 * Set the permission factory to use when recreating {@link AccessControlEntry}s
	 * @param permissionFactory
	 */
	public void setPermissionFactory(final PermissionFactory permissionFactory) {
		this.permissionFactory = permissionFactory;
	}
	
}
