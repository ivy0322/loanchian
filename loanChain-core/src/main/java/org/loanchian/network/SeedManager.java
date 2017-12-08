package org.loanchian.network;

import java.util.List;

/**
 * 种子节点管理
 * @author ln
 *
 */
public interface SeedManager {

	/**
	 * 添加一个种子节点
	 * @param seed
	 * @return boolean
	 */
	boolean add(Seed seed);
	
	/**
	 * 添加一个dns种子
	 * @param domain
	 * @return boolean
	 */
	boolean addDnsSeed(String domain);
	
	/**
	 * 获取一个可用的种子节点列表
	 * @param maxConnectionCount 最大数量
	 * @return List<Seed>
	 */
	List<Seed> getSeedList(int maxConnectionCount);

	/**
	 * 获取所有的节点，不管可不可用
	 * @return
	 */
	List<Seed> getAllSeeds();

	/**
	 * 是否有更多的可用节点
	 * @return boolean
	 */
	boolean hasMore();
	
	/**
	 * 重置种子节点
	 */
	void reset();
}
