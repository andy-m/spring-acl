package spring.acl.util.reflect;

import java.lang.reflect.Method;

import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.AuthenticationServiceException;

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
