package spring.acl.hbase.repository;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;


public class TestingInMemoryCache implements AclCache {

	private final Map<Serializable, MutableAcl> cache = new HashMap<Serializable, MutableAcl>();
	
	@Override
	public void evictFromCache(final Serializable pk) {
		cache.remove(pk);
	}

	@Override
	public void evictFromCache(final ObjectIdentity objectIdentity) {
		evictFromCache(objectIdentity.getIdentifier());
	}

	@Override
	public MutableAcl getFromCache(final ObjectIdentity objectIdentity) {
		return getFromCache(objectIdentity.getIdentifier());
	}

	@Override
	public MutableAcl getFromCache(final Serializable pk) {
		return cache.get(pk);
	}

	@Override
	public void putInCache(final MutableAcl acl) {
		cache.put(acl.getObjectIdentity().getIdentifier(), acl);
	}

	@Override
	public void clearCache() {
		cache.clear();
	}

}
