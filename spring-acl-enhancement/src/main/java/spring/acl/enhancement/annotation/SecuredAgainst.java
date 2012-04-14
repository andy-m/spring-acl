package spring.acl.enhancement.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Specifies the class against which the method should be secured.
 * 
 * @author Andy Moody
 */

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface SecuredAgainst {

	Class<?> value();
	
}
