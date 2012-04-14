package spring.acl.enhancement.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Specifies that the annotated parameter or method
 * provides an object which can be used as a Secure Object Id
 * 
 * The internalMethod, if specified, defines a method which should
 * be called on the resolved object to retrieve the id.
 * 
 * @author Andy Moody
 */

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.PARAMETER})
public @interface SecuredId {

	String internalMethod() default "";
	
}
