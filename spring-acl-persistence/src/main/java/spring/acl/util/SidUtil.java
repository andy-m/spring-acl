package spring.acl.util;

import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;


public class SidUtil {
	
	public static String resolveAuthority(final Sid sid) {
		String authority;
		if(sid instanceof PrincipalSid){
			authority = ((PrincipalSid) sid).getPrincipal();
		}else{
			authority = ((GrantedAuthoritySid) sid).getGrantedAuthority();
		}
		return authority;
	}
	
	public static boolean isPrincipal(final Sid sid){
		return sid instanceof PrincipalSid;
	}
	
	public static Sid createSid(final String authority, final boolean principal){
		Sid toReturn = null;
		if(principal){
			toReturn = new PrincipalSid(authority);
		}else{
			toReturn = new GrantedAuthoritySid(authority);
		}
		return toReturn; 
	}

}
