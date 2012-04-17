/**
 * 
 */
package spring.acl.entity;

import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;


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
 * Extension of the MutableAcl which provides some additional methods
 * aimed at making creation / management of acl's easier.
 *
 * @author Andy Moody
 */
public interface SimpleMutableAcl extends MutableAcl {

	/**
	 * Inserts granting ace's for the specified permissions at the end of the ace collection.
	 * Remaining permissions will be added sequentially after the first permission
	 */
	public void insertGrantedPermissions(Sid sid, Permission... permissions);

	/**
	 * Inserts denying ace's for the specified permissions at the end of the ace collection.
	 * Remaining permissions will be added sequentially after the first permission
	 */
	public void insertDeniedPermissions(Sid sid, Permission... permissions);
	
	/**
	 * Inserts granting ace's for the specified permissions starting at the specified position.
	 * Remaining permissions will be added sequentially after the first permission 
	 */
	public void insertGrantedPermissions(Sid sid, int firstPermissionPosition, Permission... permissions);
	
	/**
	 * Inserts denying ace's for the specified permissions starting at the specified position.
	 * Remaining permissions will be added sequentially after the first permission
	 */
	public void insertDeniedPermissions(Sid sid, int firstPermissionPosition, Permission... permissions);

}
