package spring.acl.hbase.repository;

/**
 * Class representing the key of an AccessControlEntry
 * in the HBase schema. 
 * The AccessControlEntries are stored in qualifiers
 * against the Acl row and we don't need to retrieve
 * them individually so we simply store each ace
 * against the position it appears in the list.
 * 
 * @author Andy Moody
 */
public class AccessControlEntryKey {
	
	private final byte[] key;
	private final int position;
	
	public AccessControlEntryKey(final int position) {
		this.position = position;
		this.key = createKey(position);
	}
	
	public AccessControlEntryKey(final byte[] key){
		String keyString = new String(key);
		this.position = Integer.valueOf(keyString);
		this.key = key;
	}
	
	public byte[] getKey() {
		return key;
	}
	
	public int getPosition() {
		return position;
	}
	
	private static byte[] createKey(final int position) {
		StringBuilder builder = new StringBuilder();
		builder.append(position);
		return builder.toString().getBytes();
	}
	
}
