package spring.acl.util.reflect;

import java.lang.reflect.Method;

import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.AuthenticationServiceException;


public class MethodUtil {
	
	public static Object invoke(final Object domainObject, final String methodName) {
		Method method = getMethod(domainObject, methodName);
		return invoke(method, domainObject);
	}
	
	public static Method getMethod(final Object domainObject, final String internalMethod, final Class<?>...argTypes) {
		return getMethod(domainObject.getClass(), internalMethod, argTypes);
	}
	
	public static Method getMethod(final Class<?> clazz, final String internalMethod, final Class<?>...argTypes) {
		try {
			return clazz.getMethod(internalMethod, argTypes);
		} catch (NoSuchMethodException nsme) {
			throw new AuthorizationServiceException("Object of class '" + clazz
					+ "' does not provide the requested method: " + internalMethod);
		}
	}

	public static Object invoke(final Method method, final Object target, final Object... args) {
		Object providedArgument = null;
		if (target != null)
		{
			try
			{
				providedArgument = method.invoke(target, args);
			}
			catch (Exception e)
			{
				throw new AuthenticationServiceException("Exception invoking method " + method, e);
			}
		}
		return providedArgument;
	}

}
