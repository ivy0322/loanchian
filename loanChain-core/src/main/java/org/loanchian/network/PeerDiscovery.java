package org.loanchian.network;

import org.loanchian.core.PeerAddress;

import java.util.List;

/**
 * 节点发现服务接口
 * @author ln
 *
 */
public interface PeerDiscovery {
	
	/**
	 * 启动
	 */
	void startSync();
	
	/**
	 * 程序关闭时，持久化内存里面的节点信息到文件
	 */
	void shutdown();
	
	/**
	 * 添加一个节点
	 * @param peerAddress
	 */
	boolean add(PeerAddress peerAddress);
	
	/**
	 * 添加一个节点
	 * @param peerAddress
	 * @param hasVerify 是否已经验证
	 */
	boolean add(PeerAddress peerAddress, boolean hasVerify);

	/**
	 * 批量添加节点，未经验证的
	 * @param addresses
	 */
	void addBath(List<PeerAddress> addresses);

	/**
	 * 获取可用的节点列表，最大返回1024个
	 * @return List<PeerAddress>
	 */
	List<PeerAddress> getAvailablePeerAddress();
	
	/**
	 * 获取可用的节点列表
	 * @param maxCount	最多返回数量
	 * @return List<PeerAddress>
	 */
	List<PeerAddress> getAvailablePeerAddress(int maxCount);
	
	/**
	 * 获取可连接的节点列表
	 * @return List<Seed>
	 */
	List<Seed> getCanConnectPeerSeeds();

	/**
	 * 获取可连接的节点列表
	 * @return List<Seed>
	 */
	List<Seed> getCanConnectPeerSeeds(int maxCount);
	
	/**
	 * 节点是否已经存在（已被发现）
	 * @param peerAddress
	 * @return boolean
	 */
	boolean hasExist(PeerAddress peerAddress);

	/**
	 * 刷新节点的连接状态
	 * @param seed
	 */
	void refreshSeedStatus(Seed seed);

	/**
	 * 检查本机服务是否对外提供，如果提供则上传
	 */
	void checkMyserviceAndReport();

	/**
	 * 重置节点信息
	 * 该方法会清楚本地保存的节点，在重置本地数据时会调用
	 */
	void reset();

	/**
	 * 获取DNS种子节点
	 * @param maxCount
	 * @return
	 */
	List<Seed> getDnsSeeds(int maxCount);

	/**
	 * 获取所有种子节点
	 * @return
	 */
	List<Seed> getAllSeeds();
}
