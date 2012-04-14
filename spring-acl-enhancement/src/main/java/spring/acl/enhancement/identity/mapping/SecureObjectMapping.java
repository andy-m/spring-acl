package spring.acl.enhancement.identity.mapping;

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
 * Interface allowing us to separate the object which
 * is the identifier or contains the identifier from the
 * class we want to check security against.
 * 
 * This allows us to do nice things like checking security
 * against the id of an entity without needing to load the
 * entity first.
 * 
 * @author Andy Moody
 */
public interface SecureObjectMapping {
	
	Object getDomainObject();
	Class<?> getSecuredClass();
	
}
