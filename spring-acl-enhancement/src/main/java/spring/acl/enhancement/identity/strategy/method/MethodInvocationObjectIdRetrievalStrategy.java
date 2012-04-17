package spring.acl.enhancement.identity.strategy.method;

import org.aopalliance.intercept.MethodInvocation;
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
 * Immitates the {@link ObjectIdentityRetrievalStrategy} from the spring framework
 * but seeks to resolve the ObjectIdentity from the method invocation
 * rather than a domain object.
 * 
 * This is more flexible since it allows our strategies to determine
 * exactly how {@link ObjectIdentity} objects should be retrieved - rather than relying
 * on the existing spring domain object resolution.
 * 
 * Implementations may return null if no identity is available;
 * 
 * @author Andy Moody
 */
public interface MethodInvocationObjectIdRetrievalStrategy {

	 ObjectIdentity getObjectIdentity(MethodInvocation invocation);
	 
}
