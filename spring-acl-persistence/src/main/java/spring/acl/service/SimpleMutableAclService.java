/**
 * 
 */
package spring.acl.service;

import org.springframework.security.acls.domain.SimpleMutableAcl;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;


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
 *
 *
 * @author Andy Moody
 */
public interface SimpleMutableAclService extends MutableAclService {
	
	/**
	 * Overloads the updateAcl method from {@link MutableAclService}
	 */
	SimpleMutableAcl updateAcl(final SimpleMutableAcl acl) throws NotFoundException;
	
	/* (non-Javadoc)
	 * @see org.springframework.security.acls.model.MutableAclService#createAcl(org.springframework.security.acls.model.ObjectIdentity)
	 */
	@Override
	SimpleMutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException;
	

}
