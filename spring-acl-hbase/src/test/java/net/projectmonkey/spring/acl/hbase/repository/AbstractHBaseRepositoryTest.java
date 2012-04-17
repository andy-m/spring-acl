package net.projectmonkey.spring.acl.hbase.repository;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import junit.framework.Assert;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.client.HTablePool;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;

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
 * Abstract class for integration testing against HBase tables. The static
 * methods herein will create and delete the required hbase tables and families
 * when called. They are designed to be called once only from static
 * initialization and destruction methods.
 * 
 * Implementations of this class are expected to handle tear down of their test
 * data between test methods if they need to do so, though we do also provide a
 * utility method for doing this here.
 */
public abstract class AbstractHBaseRepositoryTest {

	private static HTablePool pool;
	private static HBaseAdmin admin;

	protected static void createTables(final Map<String, List<String>> tablesAndFamilies) throws IOException {
		Assert.assertNotNull(tablesAndFamilies);
		Configuration config = HBaseConfiguration.create();
		config.set("hbase.zookeeper.quorum", "localhost");
		if (pool == null)
		{
			pool = new HTablePool(config, 2);
		}
		if (admin == null)
		{
			admin = new HBaseAdmin(config);
			for (Entry<String, List<String>> table : tablesAndFamilies.entrySet())
			{
				String tableName = table.getKey();
				List<String> families = table.getValue();
				createTable(tableName, families);
			}
		}
	}

	protected static void deleteTables(final Map<String, List<String>> tablesAndFamilies) throws IOException {
		for (String tableName : tablesAndFamilies.keySet())
		{
			admin.disableTable(tableName);
			admin.deleteTable(tableName);
		}
	}

	protected static void clearAllTables(final Map<String, List<String>> tablesAndFamilies) throws IOException {
		for (Entry<String, List<String>> tableAndFamilies : tablesAndFamilies.entrySet())
		{
			HTableInterface table = pool.getTable(tableAndFamilies.getKey());
			try
			{
				ResultScanner scanner = table.getScanner(new Scan());
				Iterator<Result> iterator = scanner.iterator();
				Result result = null;
				while ((result = iterator.next()) != null)
				{
					if (!result.isEmpty())
					{
						table.delete(new Delete(result.getRow()));
					}
				}
			}
			finally
			{
				table.close();
			}
		}
	}

	private static void createTable(final String tableName, final List<String> families) throws IOException {
		HTableDescriptor descriptor = new HTableDescriptor(tableName);
		for (String familyName : families)
		{
			descriptor.addFamily(new HColumnDescriptor(familyName));
		}
		admin.createTable(descriptor);
	}

	protected HTablePool getPool() {
		if (pool == null)
		{
			throw new IllegalStateException(
					"No pool initialised, call createTables from a suitable static initialization method and don't forget to call clearHbase");
		}
		return pool;
	}

}
