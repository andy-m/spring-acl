package spring.acl.enhancement.identity.strategy.method.sample;

import spring.acl.enhancement.annotation.SecuredAgainst;
import spring.acl.enhancement.annotation.SecuredId;


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
