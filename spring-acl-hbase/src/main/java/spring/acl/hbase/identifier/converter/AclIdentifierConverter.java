package spring.acl.hbase.identifier.converter;

import java.io.Serializable;

public interface AclIdentifierConverter<T extends Serializable> {

	byte[] toByteArray(T identifier);
	
	T fromByteArray(byte[] bytes);
	
}
