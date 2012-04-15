package spring.acl.enhancement.voter;

import java.util.Collection;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import spring.acl.enhancement.identity.strategy.ConfigurableObjectIdentityRetrievalStrategy;
import spring.acl.enhancement.identity.strategy.method.DefaultMethodInvocationObjectIdRetrievalStrategy;
import spring.acl.enhancement.identity.strategy.method.MethodInvocationObjectIdRetrievalStrategy;

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
 * Modified version of AbstractAclVoter which simplifies, and makes more
 * flexible, the process of retrieving secured object identifiers. 
 * 
 * The objectIdentityRetrievalStrategy can be set to allow users to resolve the
 * ObjectIdentity in any way they choose from the MethodInvocation. The default
 * implementation is to extend the Spring Security implementation by allowing
 * separation of the Secured Class from the method parameter - thus allowing
 * us to use, for example, the identifier of an object passed to a method
 * to check acl permissions without actually having to physically load the object
 * from a datasource first.
 *
 * To configure this as per the standard Spring {@link org.springframework.security.acls.AclEntryVoter}
 * simply configure with the approprate processConfigAttribute and internalMethod
 * parameters set. 
 * If you want to remove the default use of 'getId()' as a final call to retrieve the id from a 
 * resolved domain object then simple configure the {@link DefaultMethodInvocationObjectIdRetrievalStrategy}  
 * with a {@link ConfigurableObjectIdentityRetrievalStrategy} specifying no constructor args to disable the call 
 * altogether or a constructor arg with the method name you'd like to use as an alternative.
 * 
 * @author Andy Moody
 */
public class AclEntryVoter implements AccessDecisionVoter<MethodInvocation> {

	private static final Log logger = LogFactory.getLog(AclEntryVoter.class);

	// ~ Instance fields
	// ================================================================================================

	private final AclService aclService;
	private final String processConfigAttribute;
	private final List<Permission> requirePermission;
	private MethodInvocationObjectIdRetrievalStrategy objectIdentityRetrievalStrategy;
	private SidRetrievalStrategy sidRetrievalStrategy;

	public AclEntryVoter(final AclService aclService, final String processConfigAttribute,
			final List<Permission> requirePermission) {
		this(aclService, processConfigAttribute, requirePermission, defaultObjectIdentityRetrievalStrategy());
	}
	
	public AclEntryVoter(final AclService aclService, final String processConfigAttribute, final List<Permission> requirePermission, 
			final MethodInvocationObjectIdRetrievalStrategy objectIdentityRetrievalStrategy) {
		this(aclService, processConfigAttribute, requirePermission, objectIdentityRetrievalStrategy, defaultSidRetrievalStrategy());
	}
	
	public AclEntryVoter(final AclService aclService, final String processConfigAttribute, final List<Permission> requirePermission, 
			final SidRetrievalStrategy sidRetrievalStrategy) {
		this(aclService, processConfigAttribute, requirePermission, defaultObjectIdentityRetrievalStrategy(), sidRetrievalStrategy);
	}
	
	public AclEntryVoter(final AclService aclService, final String processConfigAttribute, final List<Permission> requirePermission, 
			final MethodInvocationObjectIdRetrievalStrategy objectIdentityRetrievalStrategy, final SidRetrievalStrategy sidRetrievalStrategy) {
		Assert.notNull(processConfigAttribute, "A processConfigAttribute is mandatory");
		Assert.notNull(aclService, "An AclService is mandatory");
		Assert.notNull(objectIdentityRetrievalStrategy, "A MethodInvocationObjectIdRetrievalStrategy is Mandatory");
		Assert.notNull(objectIdentityRetrievalStrategy, "A SidRetrievalStrategy is Mandatory");
		Assert.isTrue(requirePermission!=null && !requirePermission.isEmpty(), "One or more requirePermission entries is mandatory");

		this.aclService = aclService;
		this.processConfigAttribute = processConfigAttribute;
		this.requirePermission = requirePermission;
		this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
		this.sidRetrievalStrategy = sidRetrievalStrategy;
	}

	// ~ Methods
	// ========================================================================================================



	@Override
	public boolean supports(final ConfigAttribute attribute) {
		return (attribute.getAttribute() != null) && attribute.getAttribute().equals(getProcessConfigAttribute());
	}

	@Override
	public int vote(final Authentication authentication, final MethodInvocation invocation,
			final Collection<ConfigAttribute> attributes) {

		for (ConfigAttribute attr : attributes)
		{

			if (!this.supports(attr))
			{
				continue;
			}

			ObjectIdentity secureObjectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity(invocation);
			if(secureObjectIdentity == null){
				if (logger.isDebugEnabled())
				{
					logger.debug("Voting to abstain - identity is null");
				}
				return ACCESS_ABSTAIN;
			}

			// Obtain the SIDs applicable to the principal
			List<Sid> sids = sidRetrievalStrategy.getSids(authentication);

			Acl acl;

			try
			{
				// Lookup only ACLs for SIDs we're interested in
				acl = aclService.readAclById(secureObjectIdentity, sids);
			}
			catch (NotFoundException nfe)
			{
				if (logger.isDebugEnabled())
				{
					logger.debug("Voting to deny access - no ACLs apply for this principal");
				}

				return ACCESS_DENIED;
			}

			return checkGranted(sids, acl);
		}

		// No configuration attribute matched, so abstain
		return ACCESS_ABSTAIN;
	}

	protected String getProcessConfigAttribute() {
		return processConfigAttribute;
	}

	public void setObjectIdentityRetrievalStrategy(final MethodInvocationObjectIdRetrievalStrategy objectIdentityRetrievalStrategy) {
		Assert.notNull(objectIdentityRetrievalStrategy, "objectIdentityRetrievalStrategy required");
		this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
	}

	public void setSidRetrievalStrategy(final SidRetrievalStrategy sidRetrievalStrategy) {
		Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
		this.sidRetrievalStrategy = sidRetrievalStrategy;
	}

	private int checkGranted(final List<Sid> sids, final Acl acl) {
		try
		{
			if (acl.isGranted(requirePermission, sids, false))
			{
				if (logger.isDebugEnabled())
				{
					logger.debug("Voting to grant access");
				}

				return ACCESS_GRANTED;
			}
			else
			{
				if (logger.isDebugEnabled())
				{
					logger.debug("Voting to deny access - ACLs returned, but insufficient permissions for this principal");
				}

				return ACCESS_DENIED;
			}
		}
		catch (NotFoundException nfe)
		{
			if (logger.isDebugEnabled())
			{
				logger.debug("Voting to deny access - no ACLs apply for this principal");
			}

			return ACCESS_DENIED;
		}
	}

	@Override
	public boolean supports(final Class<?> clazz) {
		return MethodInvocation.class.isAssignableFrom(clazz);
	}

	private static DefaultMethodInvocationObjectIdRetrievalStrategy defaultObjectIdentityRetrievalStrategy() {
		return new DefaultMethodInvocationObjectIdRetrievalStrategy();
	}

	private static SidRetrievalStrategyImpl defaultSidRetrievalStrategy() {
		return new SidRetrievalStrategyImpl();
	}
	
}
