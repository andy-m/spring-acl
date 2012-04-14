package spring.acl.hbase.identifier.converter;

import org.apache.hadoop.hbase.util.Bytes;

public class LongAclIdentifierConverter implements AclIdentifierConverter<Long>{

	@Override
	public byte[] toByteArray(final Long identifier) {
		return Bytes.toBytes(identifier);
	}

	@Override
	public Long fromByteArray(final byte[] bytes) {
		return Bytes.toLong(bytes);
	}

}
