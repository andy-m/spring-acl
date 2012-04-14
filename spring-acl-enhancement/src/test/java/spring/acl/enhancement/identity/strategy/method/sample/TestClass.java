package spring.acl.enhancement.identity.strategy.method.sample;

import spring.acl.enhancement.annotation.SecuredAgainst;
import spring.acl.enhancement.annotation.SecuredId;

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

public class TestClass {
	
	public void methodWithNoSecuredAgainst(){
		
	}
	

	public void methodWithNoSecuredAgainstAndNoMatchingParams(final Object param){
		
	}
	
	public void methodWithNoSecuredAgainstAndParamsWhichMatchBecauseOfSecuredId(@SecuredId final Object param){
		
	}

	public void methodWithNoSecuredAgainstAndParamsWhichMatchBecauseOfAssignable(final TestClass param){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithSecuredAgainstAndNoParams(){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithSecuredAgainstAndNoMatchingParams(final Object param){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithSecuredAgainstAndParamsWhichMatchBecauseOfSecuredId(@SecuredId final Object param){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithSecuredAgainstAndParamsWhichMatchBecauseOfAssignable(final TestClass param){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithMultipleSecuredIdsAndAssignables(final TestClass param, @SecuredId final Object param2, @SecuredId final Object param3){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithMultipleAssignables(final TestClass param, final TestClass param2){
		
	}
	
	@SecuredAgainst(TestClass.class)
	public void methodWithSecuredIdDefiningInternalMethod(@SecuredId(internalMethod="someOtherMethod") final TestClass param){
		
	}

}
