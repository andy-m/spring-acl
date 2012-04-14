package spring.acl.hbase.identifier.converter;

import org.apache.hadoop.hbase.util.Bytes;

public class IntegerAclIdentifierConverter implements AclIdentifierConverter<Integer>{

	@Override
	public byte[] toByteArray(final Integer identifier) {
		return Bytes.toBytes(identifier);
	}

	@Override
	public Integer fromByteArray(final byte[] bytes) {
		return Bytes.toInt(bytes);
	}

}
