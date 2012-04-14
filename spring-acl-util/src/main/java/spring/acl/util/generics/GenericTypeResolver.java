package spring.acl.util.generics;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GenericTypeResolver {

	public static Class<?> getFirstGenericTypeFrom(final Object object, final Class<?> interfaceOrSuperclassType){
		Class<?> toReturn = null;
		Type[] interfaces = object.getClass().getGenericInterfaces();
		Type superType = object.getClass().getGenericSuperclass();
		List<Type> potentialTypes = new ArrayList<Type>(Arrays.asList(interfaces));
		potentialTypes.add(superType);

		for (Type type : potentialTypes)
		{
			if (type instanceof ParameterizedType)
			{
				ParameterizedType parameterizedType = (ParameterizedType) type;
				if(interfaceOrSuperclassType.equals(parameterizedType.getRawType())){
					Type[] parameterisedTypes = parameterizedType.getActualTypeArguments();
					if (parameterisedTypes.length == 0)
					{
						throw new IllegalArgumentException("No generic arguments found for class: " + interfaceOrSuperclassType);
					}
					Type typeArg = parameterisedTypes[0];
					toReturn = (Class<?>) typeArg;
				}
			}
		}
		if(toReturn == null)
		{
			throw new IllegalArgumentException("Unable to derive generic type for class "+interfaceOrSuperclassType); 
		}
		return toReturn;
	}

}
