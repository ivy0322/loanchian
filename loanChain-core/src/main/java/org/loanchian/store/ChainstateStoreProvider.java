package org.loanchian.store;

import org.loanchian.Configure;
import org.loanchian.account.AccountBody;
import org.loanchian.account.Address;
import org.loanchian.consensus.ConsensusModel;
import org.loanchian.consensus.ConsensusPool;
import org.loanchian.core.Assets;
import org.loanchian.core.Coin;
import org.loanchian.core.ViolationEvidence;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.business.*;
import org.iq80.leveldb.DBIterator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 链状态查询提供服务，存放的是所有的未花费交易，以及共识节点
 * @author yangying
 *
 */
@Repository
public class ChainstateStoreProvider extends BaseStoreProvider {
	
	private Lock consensusLocker = new ReentrantLock();
	private Lock revokeLock  = new ReentrantLock();
	private Lock assetsLock = new ReentrantLock();
	
	@Autowired
	private BlockStoreProvider blockStoreProvider;
	@Autowired
	private ConsensusPool consensusPool;

	protected ChainstateStoreProvider() {
		this(Configure.DATA_CHAINSTATE);
	}
	
	protected ChainstateStoreProvider(String dir) {
		this(dir, -1, -1);
	}
	protected ChainstateStoreProvider(String dir, long leveldbReadCache,
			int leveldbWriteCache) {
		super(dir, leveldbReadCache, leveldbWriteCache);
	}

	@Override
	protected byte[] toByte(Store store) {
		if(store == null) {
			throw new NullPointerException("transaction is null");
		}
		TransactionStore transactionStore = (TransactionStore) store;
		
		Transaction transaction = transactionStore.getTransaction();
		if(transaction == null) {
			throw new NullPointerException("transaction is null");
		}
		return transaction.baseSerialize();
	}

	@Override
	protected Store pase(byte[] content) {
		if(content == null) {
			throw new NullPointerException("transaction content is null");
		}
		Transaction transaction = new Transaction(network, content);
		TransactionStore store = new TransactionStore(network, transaction);
		return store;
	}
	
	/**
	 * 获取账户的公钥
	 * 如果是认证账户，则获取的是最新的公钥
	 * @param hash160 账户的hash160
	 * @return byte[][] 普通账户返回1个，认证账户前两个为管理公钥、后两个为交易公钥，当没有查到时返回null
	 */
	public byte[][] getAccountPubkeys(byte[] hash160) {
		AccountStore store = getAccountInfo(hash160);
		if(store == null) {
			return null;
		} else {
			return store.getPubkeys();
		}
	}

	/**
	 * 获取账户信息
	 * @param hash160
	 * @return AccountStore
	 */
	public AccountStore getAccountInfo(byte[] hash160) {
		byte[] accountBytes = getBytes(hash160);
		if(accountBytes == null) {
			return null;
		}
		AccountStore store = new AccountStore(network, accountBytes);
		return store;
	}
	
	/**
	 * 保存账户信息
	 * @param accountInfo
	 * @return boolean
	 */
	public boolean saveAccountInfo(AccountStore accountInfo) {
		try {
			put(accountInfo.getHash160(), accountInfo.baseSerialize());
			return true;
		} catch (Exception e) {
			log.error("保存账户信息出错：", e);
			return false;
		}
	}
	


	
	/**
	 * 通过别名查询账户信息
	 * @param alias
	 * @return AccountStore
	 */
	public AccountStore getAccountInfoByAlias(byte[] alias) {
		byte[] hash160 = getAccountHash160ByAlias(alias);
		if(hash160 == null) {
			return null;
		}
		return getAccountInfo(hash160);
	}
	
	/**
	 * 通过别名查询账户hash160
	 * @param alias
	 * @return byte[]
	 */
	public byte[] getAccountHash160ByAlias(byte[] alias) {
		if(alias == null) {
			return null;
		}
		return getBytes(Sha256Hash.hash(alias));
	}
	
	/**
	 * 设置账户别名
	 * 消耗相应的信用点
	 * @param hash160
	 * @param alias
	 * @return boolean
	 */
	public boolean setAccountAlias(byte[] hash160, byte[] alias) {
		AccountStore accountInfo = getAccountInfo(hash160);
		if(accountInfo == null) {
			return false;
		}
		//设置别名
		accountInfo.setAlias(alias);
		saveAccountInfo(accountInfo);
		
		put(Sha256Hash.hash(alias), hash160);
		
		return true;
	}
	
	/**
	 * 撤销设置账户别名
	 * 消耗相应的信用点
	 * @param hash160
	 * @param alias
	 * @return boolean
	 */
	public boolean revokedSetAccountAlias(byte[] hash160, byte[] alias) {
		AccountStore accountInfo = getAccountInfo(hash160);
		if(accountInfo == null) {
			return false;
		}
		//设置别名为空
		accountInfo.setAlias(null);
		saveAccountInfo(accountInfo);
		
		put(Sha256Hash.hash(alias), hash160);
		
		return true;
	}
	
	/**
	 * 修改账户别名
	 * 消耗相应的信用点
	 * @param hash160
	 * @param alias
	 * @return boolean
	 */
	public boolean updateAccountAlias(byte[] hash160, byte[] alias) {
		AccountStore accountInfo = getAccountInfo(hash160);
		if(accountInfo == null) {
			return false;
		}
		//删除旧别名
		byte[] oldAlias = accountInfo.getAlias();
		if(oldAlias != null && oldAlias.length > 0) {
			delete(Sha256Hash.hash(accountInfo.getAlias()));
		}
		//设置新的别名
		accountInfo.setAlias(alias);
		//扣除信用
		accountInfo.setCert(accountInfo.getCert() + Configure.UPDATE_ALIAS_SUB_CREDIT);
		saveAccountInfo(accountInfo);
		
		put(Sha256Hash.hash(alias), hash160);
		
		return true;
	}
	
	/**
	 * 撤销修改账户别名
	 * 消耗相应的信用点
	 * @param hash160
	 * @param alias
	 * @return boolean
	 */
	public boolean revokedUpdateAccountAlias(byte[] hash160, byte[] alias) {
		//TODO
		//增加信用
		AccountStore accountInfo = getAccountInfo(hash160);
		if(accountInfo == null) {
			return false;
		}
		accountInfo.setCert(accountInfo.getCert() - Configure.UPDATE_ALIAS_SUB_CREDIT);
		saveAccountInfo(accountInfo);
		put(Sha256Hash.hash(alias), hash160);
		
		return true;
	}

	/**
	 * 共识节点加入
	 * @param tx
	 */
	public void addConsensus(RegConsensusTransaction tx) {
		consensusLocker.lock();
		try {
			//注册共识，加入到共识账户列表中
			byte[] consensusAccountHash160s = getBytes(Configure.CONSENSUS_ACCOUNT_KEYS);
			if(consensusAccountHash160s == null) {
				consensusAccountHash160s = new byte[0];
			}
			byte[] hash160 = tx.getHash160();
			byte[] packager = tx.getPackager();
			byte[] newConsensusHash160s = new byte[consensusAccountHash160s.length + (2 * Address.LENGTH + Sha256Hash.LENGTH)];
			System.arraycopy(consensusAccountHash160s, 0, newConsensusHash160s, 0, consensusAccountHash160s.length);
			System.arraycopy(hash160, 0, newConsensusHash160s, consensusAccountHash160s.length, Address.LENGTH);
			System.arraycopy(packager, 0, newConsensusHash160s, consensusAccountHash160s.length + Address.LENGTH, Address.LENGTH);
			System.arraycopy(tx.getHash().getBytes(), 0, newConsensusHash160s, consensusAccountHash160s.length + 2 * Address.LENGTH, Sha256Hash.LENGTH);
			put(Configure.CONSENSUS_ACCOUNT_KEYS, newConsensusHash160s);

			//添加账户信息，如果不存在的话
			AccountStore accountInfo = getAccountInfo(hash160);
			if(accountInfo == null) {
				//理论上只有普通账户才有可能没信息，注册账户没有注册信息的话，交易验证不通过
				accountInfo = createNewAccountInfo(tx, AccountBody.empty(), new byte[][] {tx.getPubkey()});
				accountInfo.setSupervisor(null);
				accountInfo.setLevel(0);
				put(hash160, accountInfo.baseSerialize());
			} else {
				//不确定的账户，现在可以确定下来了
				updateAccountInfo(accountInfo, tx);
			}
			//添加到共识缓存器里
			consensusPool.add(new ConsensusModel(tx.getHash(), tx.getHash160(), tx.getPackager()));
		} catch (Exception e) {
			log.error("出错了{}", e.getMessage(), e);
		} finally {
			consensusLocker.unlock();
		}
	}
	
	/**
	 * 退出共识
	 * @param tx
	 */
	public void removeConsensus(Transaction tx) {
		byte[] hash160 = null;
		if(tx instanceof RemConsensusTransaction) {
			//主动退出共识
			RemConsensusTransaction remTransaction = (RemConsensusTransaction)tx;
			hash160 = remTransaction.getHash160();
		} else {
			//违规被提出共识
			ViolationTransaction vtx = (ViolationTransaction)tx;
			hash160 = vtx.getViolationEvidence().getAudienceHash160();
		}

		//从集合中删除共识节点
		deleteConsensusFromCollection(hash160);

		//退出的账户
		if(tx instanceof ViolationTransaction) {

			//违规被提出共识，增加规则证据到状态里，以便查证
			ViolationTransaction vtx = (ViolationTransaction)tx;
			ViolationEvidence violationEvidence = vtx.getViolationEvidence();
			Sha256Hash evidenceHash = violationEvidence.getEvidenceHash();
			put(evidenceHash.getBytes(), tx.getHash().getBytes());

			//如果是惩罚，则对委托人进行处理
			TransactionStore regTxStore = blockStoreProvider.getTransaction(tx.getInput(0).getFroms().get(0).getParent().getHash().getBytes());
			RegConsensusTransaction regtx = (RegConsensusTransaction) regTxStore.getTransaction();
			hash160 = regtx.getHash160();

			//减去相应的信用值
			AccountStore accountInfo = getAccountInfo(hash160);
			long certChange = 0;
			if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK) {
				certChange = Configure.CERT_CHANGE_TIME_OUT;
			} else if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_REPEAT_BROADCAST_BLOCK) {
				certChange = Configure.CERT_CHANGE_SERIOUS_VIOLATION;
			}
			
			accountInfo.setCert(accountInfo.getCert() + certChange);
			
			saveAccountInfo(accountInfo);
		}
	}

	/**
	 * 从集合中删除共识节点
	 * @param hash160
	 */
	public void deleteConsensusFromCollection(byte[] hash160) {
		consensusLocker.lock();
		try {
			//从共识账户列表中删除
			byte[] consensusAccountHash160s = getBytes(Configure.CONSENSUS_ACCOUNT_KEYS);
			
			byte[] newConsensusHash160s = new byte[consensusAccountHash160s.length - (2 * Address.LENGTH + Sha256Hash.LENGTH)];
			
			//找出位置在哪里
			//判断在列表里面才更新，否则就被清空了
			for (int j = 0; j < consensusAccountHash160s.length; j += (2 * Address.LENGTH + Sha256Hash.LENGTH)) {
				byte[] addressHash160 = Arrays.copyOfRange(consensusAccountHash160s, j, j + Address.LENGTH);
				byte[] packagerHash160 = Arrays.copyOfRange(consensusAccountHash160s, j + Address.LENGTH, j + 2 * Address.LENGTH);
				if(Arrays.equals(addressHash160, hash160) || Arrays.equals(packagerHash160, hash160)) {
					System.arraycopy(consensusAccountHash160s, 0, newConsensusHash160s, 0, j);
					
					int newIndex = j + 2 * Address.LENGTH + Sha256Hash.LENGTH;
					if(newIndex < consensusAccountHash160s.length) {
						System.arraycopy(consensusAccountHash160s, newIndex, newConsensusHash160s, j, consensusAccountHash160s.length - newIndex);
					}
					
					put(Configure.CONSENSUS_ACCOUNT_KEYS, newConsensusHash160s);
					break;
				}
			}
			//从共识缓存器里中移除
			consensusPool.delete(hash160);
		} catch (Exception e) {
			log.error("出错了{}", e.getMessage(), e);
		} finally {
			consensusLocker.unlock();
		}
	}

	public void addRevokeCertAccount(CertAccountRevokeTransaction tx){
		if(isCertAccountRevoked(tx.getRevokeHash160()))
			return;
		revokeLock.lock();
		try {
			byte[] revokedAccountHash160s = getBytes(Configure.REVOKED_CERT_ACCOUNT_KEYS);
			if(revokedAccountHash160s == null) {
				revokedAccountHash160s = new byte[0];
			}
			byte[] hash160 = tx.getRevokeHash160();
			byte[] byhash160 = tx.getHash160();
			byte[] newrevokedAccountHash160s = new byte[revokedAccountHash160s.length + (Address.LENGTH * 2)];
			System.arraycopy(revokedAccountHash160s, 0, newrevokedAccountHash160s, 0, revokedAccountHash160s.length);
			System.arraycopy(hash160, 0, newrevokedAccountHash160s, revokedAccountHash160s.length, Address.LENGTH);
			System.arraycopy(byhash160, 0, newrevokedAccountHash160s, revokedAccountHash160s.length+Address.LENGTH, Address.LENGTH);
			put(Configure.REVOKED_CERT_ACCOUNT_KEYS,newrevokedAccountHash160s);
		}catch (Exception e){
			log.error("出错了{}", e.getMessage(), e);
		}finally {
			revokeLock.unlock();
		}
	}

	public void deleteRevokeCertAccount(CertAccountRevokeTransaction tx){
		if(!isCertAccountRevoked(tx.getRevokeHash160()))
			return;
		revokeLock.lock();
		try {
			byte[] revokedAccountHash160s = getBytes(Configure.REVOKED_CERT_ACCOUNT_KEYS);

			byte[] hash160 = tx.getRevokeHash160();
			byte[] byhash160 = tx.getHash160();
			byte[] newrevokedAccountHash160s = new byte[revokedAccountHash160s.length - (Address.LENGTH * 2)];
			byte[] tmpbyte = new byte[Address.LENGTH];
			for(int j=0;j<revokedAccountHash160s.length;j+= Address.LENGTH * 2) {
				System.arraycopy(revokedAccountHash160s,j,tmpbyte,0,Address.LENGTH);
				if(hash160.equals(tmpbyte)){
					System.arraycopy(revokedAccountHash160s,0,newrevokedAccountHash160s,0,j);
					System.arraycopy(revokedAccountHash160s,j+2*Address.LENGTH , newrevokedAccountHash160s,j,revokedAccountHash160s.length-j-2*Address.LENGTH);
					break;
				}
			}
			put(Configure.REVOKED_CERT_ACCOUNT_KEYS,newrevokedAccountHash160s);
		}catch (Exception e){
			log.error("出错了{}", e.getMessage(), e);
		}finally {
			revokeLock.unlock();
		}
	}

	public boolean isCertAccountRevoked(byte[] hash160){
		byte[] revokedAccountHash160s = getBytes(Configure.REVOKED_CERT_ACCOUNT_KEYS);
		if(revokedAccountHash160s == null)
			return false;

		for (int j = 0; j < revokedAccountHash160s.length; j += (Address.LENGTH *2)) {
			byte[] addressHash160 = Arrays.copyOfRange(revokedAccountHash160s, j, j + Address.LENGTH);
			if(Arrays.equals(hash160,addressHash160))
				return true;
		}
		return false;
	}


	
	/**
	 * 不确定的账户，确定下来
	 * @param accountInfo
	 * @param tx
	 */
	public void updateAccountInfo(AccountStore accountInfo, BaseCommonlyTransaction tx) {
		if(accountInfo != null && accountInfo.getType() == 0) {
			accountInfo.setType(tx.isSystemAccount() ? network.getSystemAccountVersion() : network.getCertAccountVersion());
			
			if(tx.isCertAccount()) {
				accountInfo.setInfoTxid(tx.getHash());
				CertAccountRegisterTransaction rtx = (CertAccountRegisterTransaction) tx;
				byte[][] pubkeys = new byte[][] {rtx.getMgPubkeys()[0], rtx.getMgPubkeys()[1], rtx.getTrPubkeys()[0], rtx.getTrPubkeys()[1]};
				accountInfo.setPubkeys(pubkeys);
			} else {
				accountInfo.setPubkeys(new byte[][] { tx.getPubkey() });
			}
			saveAccountInfo(accountInfo);
		}
	}
	
	/**
	 * 创建一个新的账户存储信息
	 * @param tx
	 * @param accountBody
	 * @param pubkeys
	 * @return AccountStore
	 */
	public AccountStore createNewAccountInfo(BaseCommonlyTransaction tx, AccountBody accountBody, byte[][] pubkeys) {
		AccountStore accountInfo = new AccountStore(network);
		accountInfo.setHash160(tx.getHash160());
		accountInfo.setType(tx.isSystemAccount() ? network.getSystemAccountVersion() : network.getCertAccountVersion());
		accountInfo.setStatus((byte)0);
		accountInfo.setCert(0);
		accountInfo.setAccountBody(accountBody);
		accountInfo.setBalance(Coin.ZERO.value);
		accountInfo.setCreateTime(tx.getTime());
		accountInfo.setLastModifyTime(tx.getTime());
		accountInfo.setInfoTxid(tx.getHash());
		accountInfo.setPubkeys(pubkeys);
		return accountInfo;
	}

	/**
	 * 回滚过程中的共识重新加入
	 * @param tx
	 */
	public void revokedConsensus(Transaction tx) {
		
		byte[] hash160 = null;
//		if(tx instanceof RemConsensusTransaction) {
//
//			//主动退出共识
//			RemConsensusTransaction remTransaction = (RemConsensusTransaction) tx;
//			hash160 = remTransaction.getHash160();
//
//		} else {
//
//			//违规被提出共识
//			ViolationTransaction vtx = (ViolationTransaction) tx;
//			hash160 = vtx.getViolationEvidence().getAudienceHash160();
//		}
		
		//重新加入共识账户列表中
		//注册共识的交易
		Sha256Hash txhash = tx.getInput(0).getFroms().get(0).getParent().getHash();
		
		TransactionStore regTxStore = blockStoreProvider.getTransaction(txhash.getBytes());
		if(regTxStore == null) {
			return;
		}
		RegConsensusTransaction regTx = (RegConsensusTransaction) regTxStore.getTransaction();
		
		addConsensus(regTx);
		
		//退出的账户
		if(tx instanceof ViolationTransaction) {
			//委托人
			hash160 = regTx.getHash160();

			//违规被提出共识，删除证据
			ViolationTransaction vtx = (ViolationTransaction)tx;
			ViolationEvidence violationEvidence = vtx.getViolationEvidence();
			Sha256Hash evidenceHash = violationEvidence.getEvidenceHash();
			delete(evidenceHash.getBytes());
			
			//加上之前减去的信用值
			AccountStore accountInfo = getAccountInfo(hash160);
			long certChange = 0;
			if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK) {
				certChange = Configure.CERT_CHANGE_TIME_OUT;
			} else if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_REPEAT_BROADCAST_BLOCK) {
				certChange = Configure.CERT_CHANGE_SERIOUS_VIOLATION;
			}
			accountInfo.setCert(accountInfo.getCert() - certChange);
			saveAccountInfo(accountInfo);
		}
	}

	public void clean() {
		//清除老数据
		DBIterator iterator = db.getSourceDb().iterator();
		while(iterator.hasNext()) {
			Entry<byte[], byte[]> item = iterator.next();
			byte[] key = item.getKey();
			delete(key);
		}
	}
}
