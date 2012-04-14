package spring.acl.enhancement.identity.mapping;

import java.io.Serializable;


@SuppressWarnings("serial")
public class SimpleTestClass implements Serializable {
	
	public static final String ID = "Some ID";
	
	public Object getId(){
		return ID;
	}

}
