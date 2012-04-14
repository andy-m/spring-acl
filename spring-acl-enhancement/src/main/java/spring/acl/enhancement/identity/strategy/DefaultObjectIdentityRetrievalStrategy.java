package spring.acl.enhancement.identity.strategy;

import java.io.Serializable;

/**
 * Extended version of {@link ConfigurableObjectIdentityRetrievalStrategy}
 * which provides the same behaviour as Spring does by default - i.e. that
 * the identifier / domain object must provide a getId method which returns
 * the {@link Serializable} identifier 
 * @author Andy Moody
 */
public class DefaultObjectIdentityRetrievalStrategy extends ConfigurableObjectIdentityRetrievalStrategy{
	
	public DefaultObjectIdentityRetrievalStrategy(){
		super("getId");
	}

}
