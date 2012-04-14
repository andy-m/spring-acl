package spring.acl.hbase.identifier.converter;

import org.apache.hadoop.hbase.util.Bytes;

public class StringAclIdentifierConverter implements AclIdentifierConverter<String>{

	@Override
	public byte[] toByteArray(final String identifier) {
		return Bytes.toBytes(identifier);
	}

	@Override
	public String fromByteArray(final byte[] bytes) {
		return Bytes.toString(bytes);
	}

}
