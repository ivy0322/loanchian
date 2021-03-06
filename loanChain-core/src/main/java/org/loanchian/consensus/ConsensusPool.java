package org.loanchian.consensus;

import org.loanchian.crypto.Sha256Hash;

import java.util.List;

/**
 * 共识池，维护所有参与共识的人，符合条件的人可随时加入，随时退出
 * @author ln
 *
 */
public interface ConsensusPool {

	/**
	 * 新增共识结点
	 * @param consensusModel
	 */
	void add(ConsensusModel consensusModel);
	
	/**
	 * 移除共识节点
	 */
	void delete(byte[] hash160);

	/**
	 * 判断是否是共识节点
	 * @param hash160
	 * @return boolean
	 */
	boolean contains(byte[] hash160);

	/**
	 * 判断是否是共识打包节点
	 * @param hash160
	 * @return boolean
	 */
	boolean isPackager(byte[] hash160);
	
	/**
	 * 获取共识节点的公钥
	 * @param hash160
	 * @return byte[][]
	 */
	byte[][] getPubkey(byte[] hash160);

	/**
	 * 当前共识节点列表快照
	 * @return List<ConsensusAccount>
	 */
	List<ConsensusAccount> listSnapshots();
	
	/**
	 * 获取当前共识人数
	 * @return int
	 */
	int getCurrentConsensus();
	
	/**
	 * 获取注册共识的交易hash
	 * @param hash160
	 * @return Sha256Hash
	 */
	Sha256Hash getTx(byte[] hash160);
	
	/**
	 * 清除共识数据
	 */
	void clearAll();

	/**
	 * 获取最新共识列表
	 * @return List<ConsensusModel>
	 */
	List<ConsensusModel> getContainer();
}
