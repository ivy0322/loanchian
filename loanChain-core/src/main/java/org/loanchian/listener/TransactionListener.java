package org.loanchian.listener;

import org.loanchian.store.TransactionStore;

import java.util.List;

/**
 * 交易监听器，监听新交易的产生
 * @author ln
 *
 */
public abstract class TransactionListener {

	//空实现，需要的重载
	
	/**
	 * 交易完成
	 */
	public void onComplete(TransactionStore tx) {
	}
	
	/**
	 * 新交易
	 * @param tx
	 */
	public void newTransaction(TransactionStore tx) {
	}
	
	/**
	 * 回滚交易
	 * @param txs
	 */
	public void revokedTransaction(TransactionStore txs) {
	}
	
	/**
	 * 刷新新交易列表
	 * @param mineTxList
	 */
	public void refreshTransaction(List<TransactionStore> mineTxList) {
	}
}
