package net.projectmonkey.spring.acl.hbase.identifier.converter;

import java.io.Serializable;

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
 * Interface providing the ability to convert to and from a byte[]
 * and the specified Serializable identifier type.
 * 
 * @author Andy Moody
 *
 * @param <T extends Serializable>
 */
public interface AclIdentifierConverter<T extends Serializable> {

	byte[] toByteArray(T identifier);
	
	T fromByteArray(byte[] bytes);
	
}
