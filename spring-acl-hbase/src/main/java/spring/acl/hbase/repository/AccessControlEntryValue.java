package spring.acl.hbase.repository;

import java.util.UUID;

import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

import spring.acl.util.SidUtil;

/**
 * Class representing the value of an {@link AccessControlEntry}
 * in the HBase table.
 * Since we store ACE's as column values in the Acl row the
 * constituent elements are combined into a byte array
 * representing a string of the form:
 * 
 * id:authority:principal(true/false):permissionMask:granting(true/false)
 * 
 * @author Andy Moody
 */
public class AccessControlEntryValue {
	
	private static final String SEPARATOR = ":";
	private final boolean granting;
	private final byte[] key;
	private final UUID id;
	private final Sid sid;
	private final Permission permission;
	private final String authority;
	
	public AccessControlEntryValue(final UUID id, final Sid sid, final Permission permission, final boolean granting) {
		Assert.notNull(id, "id must not be null");
		Assert.notNull(sid, "sid must not be null");
		Assert.notNull(permission, "permission must not be null");
		String authority = SidUtil.resolveAuthority(sid);
		this.id = id;
		this.sid = sid;
		this.permission = permission;
		this.granting = granting;
		this.authority = authority;
		this.key = createKey(id, authority, sid, permission, granting);
	}

	public AccessControlEntryValue(final byte[] key, final PermissionFactory permissionFactory){
		Assert.notNull(key, "key must not be null");
		Assert.notNull(permissionFactory, "permissionFactory must not be null");
		String keyString = new String(key);
		String[] values = keyString.split(SEPARATOR);
		String authority = values[1];
		boolean principal = Boolean.valueOf(values[2]);
		int permissionMask = Integer.parseInt(values[3]);
		
		Assert.isTrue(values.length == 5, "Key must consist of 5 values separated by :");
		
		this.id = UUID.fromString(values[0]);
		this.sid = SidUtil.createSid(authority, principal);
		this.permission = permissionFactory.buildFromMask(permissionMask);
		this.granting = Boolean.valueOf(values[4]);
		this.authority = authority;
		this.key = key;
	}
	
	public boolean isGranting() {
		return granting;
	}

	public byte[] getKey() {
		return key;
	}
	
	public UUID getId() {
		return id;
	}
	
	public Sid getSid() {
		return sid;
	}
	
	public Permission getPermission() {
		return permission;
	}
	
	public String getAuthority() {
		return authority;
	}

	private byte[] createKey(final UUID id, final String authority, final Sid sid, final Permission permission, final boolean granting) {
		StringBuilder builder = new StringBuilder(id.toString());
		builder.append(SEPARATOR);
		builder.append(authority);
		builder.append(SEPARATOR);
		builder.append(SidUtil.isPrincipal(sid));
		builder.append(SEPARATOR);
		builder.append(permission.getMask());
		builder.append(SEPARATOR);
		builder.append(granting);
		return builder.toString().getBytes();
	}
	
}
