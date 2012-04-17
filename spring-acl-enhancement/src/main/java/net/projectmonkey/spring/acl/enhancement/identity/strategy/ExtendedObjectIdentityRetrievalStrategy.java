package net.projectmonkey.spring.acl.enhancement.identity.strategy;

import net.projectmonkey.spring.acl.enhancement.identity.mapping.SecureObjectMapping;

import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;


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
 * Extension of {@link ObjectIdentityRetrievalStrategy}
 * which allows us to get an {@link ObjectIdentity} from a 
 * {@link SecureObjectMapping} as well as from a domain object.
 * 
 * Thus allowing us to separate the secured object from the object
 * we use to check security against that object - e.g. being able to
 * check the security of a domain object by simply supplying a String id.
 * 
 * @author Andy Moody
 */
public interface ExtendedObjectIdentityRetrievalStrategy extends ObjectIdentityRetrievalStrategy{

	ObjectIdentity getObjectIdentity(SecureObjectMapping mapping);
	
}
