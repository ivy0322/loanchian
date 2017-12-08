package org.loanchian.core;

import org.loanchian.message.*;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.business.*;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * 协议定义
 * @author ln
 *
 */
public final class Definition {


	/**
     * Inchain 核心程序版本
     */
    public static final String INCHAIN_VERSION = "1.03";

    /**
     * 版本完整信息
     */
    public static final String LIBRARY_SUBVER = "inchain core v" + INCHAIN_VERSION + "";
    
	public static final long VERSION = 1;
	
	/**
	 * 区块最大限制
	 */
	public static final int MAX_BLOCK_SIZE = 2 * 1024 * 1024;

	public static final int MIN_BLOCK_SIZE = 512*1024;
	
	/** lockTime 小于该值的代表区块高度，大于该值的代表时间戳（毫秒） **/
	public static final long LOCKTIME_THRESHOLD = 500000000L;

	/** 转账最低手续费,0.1个INS */
	public static final Coin MIN_PAY_FEE = Coin.COIN.divide(10);
	
	public static final int TYPE_COINBASE = 1;					//coinbase交易
	public static final int TYPE_PAY = 2;						//普通支付交易
	public static final int TYPE_REG_CONSENSUS = 3;				//注册成为共识节点
	public static final int TYPE_REM_CONSENSUS = 4;				//注销共识节点
	public static final int TYPE_VIOLATION = 5;					// 违规事件处理
	/** 信用累积 **/
	public static final int TYPE_CREDIT = 6;
	/** 注册别名 **/
	public static final int TYPE_REG_ALIAS = 7;
	/** 修改别名 **/
	public static final int TYPE_UPDATE_ALIAS = 8;
	
	/** 认证账户注册 **/
	public static final int TYPE_CERT_ACCOUNT_REGISTER = 11;
	/** 认证账户修改信息 **/
	public static final int TYPE_CERT_ACCOUNT_UPDATE = 12;
	/** 商家关联子账户 **/
	public static final int TYPE_RELEVANCE_SUBACCOUNT = 13;
	/** 商家解除子账户的关联 **/
	public static final int TYPE_REMOVE_SUBACCOUNT = 14;

	public static final int TYPE_CERT_ACCOUNT_REVOKE = 15;


	/** 资产登记 **/
	public static final int TYPE_ASSETS_REGISTER = 30;
	/** 资产发行 **/
	public static final int TYPE_ASSETS_ISSUED = 31;
	/** 资产转让 **/
	public static final int TYPE_ASSETS_TRANSFER = 32;
	
	public static final int TX_VERIFY_MG = 1;				//脚本认证，账户管理类
	public static final int TX_VERIFY_TR = 2;				//脚本认证，交易类
	
	/**
	 * 违规类型， 重复打包
	 */
	public final static int PENALIZE_REPEAT_BLOCK = 1;
	/**
	 * 违规类型， 垃圾块攻击
	 */
	public final static int PENALIZE_RUBBISH_BLOCK = 2;
	/**
	 * 违规类型， 打包不合法交易
	 */
	public final static int PENALIZE_ILLEGAL_TX = 3;
	

	/** 转账获得信用值 **/
	public static final int CREDIT_TYPE_PAY = 1;
	/** 持续在线获得信用值 **/
	public static final int CREDIT_TYPE_ONLINE = 2;
	
	/**
	 * 判断传入的交易是否跟代币有关
	 * @param type
	 * @return boolean
	 */
	public static boolean isPaymentTransaction(int type) {
		return type == TYPE_COINBASE || type == TYPE_PAY || type == TYPE_REG_CONSENSUS
				|| type == TYPE_REM_CONSENSUS || type == TYPE_VIOLATION || type == TYPE_ASSETS_REGISTER;
	}
	
	//交易关联
	public static final Map<Integer, Class<? extends Message>> TRANSACTION_RELATION = new HashMap<Integer, Class<? extends Message>>();
	//消息命令关联
	public static final Map<Class<? extends Message>, String> MESSAGE_COMMANDS = new HashMap<Class<? extends Message>, String>();
	//命令消息关联
	public static final Map<String, Class<? extends Message>> COMMANDS_MESSAGE = new HashMap<String, Class<? extends Message>>();
	//消息对应处理器
    public static final Map<Class<? extends Message>, String> PROCESS_FACTORYS = new HashMap<Class<? extends Message>, String>();
	//交易命令
	public static final Set<String> TRANSACTION_COMMANDS = new HashSet<>();

	static {
    	//===========================-分割线=============================//
		
		PROCESS_FACTORYS.put(PingMessage.class, "pingMessageProcess");
    	PROCESS_FACTORYS.put(PongMessage.class, "pongMessageProcess");
    	PROCESS_FACTORYS.put(VersionMessage.class, "versionMessageProcess");
    	PROCESS_FACTORYS.put(VerackMessage.class, "verackMessageProcess");
    	PROCESS_FACTORYS.put(Block.class, "blockMessageProcess");
    	PROCESS_FACTORYS.put(GetBlocksMessage.class, "getBlocksMessageProcess");
    	PROCESS_FACTORYS.put(NewBlockMessage.class, "newBlockMessageProcess");
    	PROCESS_FACTORYS.put(ConsensusMessage.class, "consensusMessageProcess");
    	PROCESS_FACTORYS.put(InventoryMessage.class, "inventoryMessageProcess");
    	PROCESS_FACTORYS.put(GetDatasMessage.class, "getDatasMessageProcess");
    	PROCESS_FACTORYS.put(DataNotFoundMessage.class, "dataNotFoundMessageProcess");

    	PROCESS_FACTORYS.put(AddressMessage.class, "addressMessageProcess");
    	PROCESS_FACTORYS.put(GetAddressMessage.class, "addressMessageProcess");
    	
    	PROCESS_FACTORYS.put(Transaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(RegAliasTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(UpdateAliasTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(CertAccountRegisterTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(CertAccountUpdateTransaction.class, "transactionMessageProcess");
		PROCESS_FACTORYS.put(CertAccountRevokeTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(RelevanceSubAccountTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(RemoveSubAccountTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(RegConsensusTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(RemConsensusTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(ViolationTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(CreditTransaction.class, "transactionMessageProcess");
    	
    	//业务消息处理器
    	PROCESS_FACTORYS.put(AssetsIssuedTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(AssetsRegisterTransaction.class, "transactionMessageProcess");
    	PROCESS_FACTORYS.put(AssetsTransferTransaction.class, "transactionMessageProcess");

    	//===========================-分割线=============================//
    	
    	MESSAGE_COMMANDS.put(PingMessage.class, "ping");
    	MESSAGE_COMMANDS.put(PongMessage.class, "pong");
    	MESSAGE_COMMANDS.put(VersionMessage.class, "version");
    	MESSAGE_COMMANDS.put(VerackMessage.class, "verack");
    	MESSAGE_COMMANDS.put(AddressMessage.class, "addr");
    	MESSAGE_COMMANDS.put(GetAddressMessage.class, "getaddr");
    	MESSAGE_COMMANDS.put(Block.class, "block");
    	MESSAGE_COMMANDS.put(GetBlocksMessage.class, "getblock");
    	MESSAGE_COMMANDS.put(NewBlockMessage.class, "newblock");
    	MESSAGE_COMMANDS.put(ConsensusMessage.class, "consensus");
    	MESSAGE_COMMANDS.put(InventoryMessage.class, "inv");
    	MESSAGE_COMMANDS.put(GetDatasMessage.class, "getdatas");
    	MESSAGE_COMMANDS.put(DataNotFoundMessage.class, "notfound");

		MESSAGE_COMMANDS.put(Transaction.class, "tx_0");
		MESSAGE_COMMANDS.put(RegAliasTransaction.class, "tx_" + TYPE_REG_ALIAS);
		MESSAGE_COMMANDS.put(UpdateAliasTransaction.class, "tx_" + TYPE_UPDATE_ALIAS);
		MESSAGE_COMMANDS.put(CertAccountRegisterTransaction.class, "tx_" + TYPE_CERT_ACCOUNT_REGISTER);
		MESSAGE_COMMANDS.put(CertAccountUpdateTransaction.class, "tx_" + TYPE_CERT_ACCOUNT_UPDATE);
		MESSAGE_COMMANDS.put(CertAccountRevokeTransaction.class, "tx_" + TYPE_CERT_ACCOUNT_REVOKE);
		MESSAGE_COMMANDS.put(RegConsensusTransaction.class, "tx_" + TYPE_REG_CONSENSUS);
		MESSAGE_COMMANDS.put(RemConsensusTransaction.class, "tx_" + TYPE_REM_CONSENSUS);
		MESSAGE_COMMANDS.put(RelevanceSubAccountTransaction.class, "tx_" + TYPE_RELEVANCE_SUBACCOUNT);
		MESSAGE_COMMANDS.put(RemoveSubAccountTransaction.class, "tx_" + TYPE_REMOVE_SUBACCOUNT);
		MESSAGE_COMMANDS.put(ViolationTransaction.class, "tx_" + TYPE_VIOLATION);
		MESSAGE_COMMANDS.put(CreditTransaction.class, "tx_" + TYPE_CREDIT);
		MESSAGE_COMMANDS.put(AssetsIssuedTransaction.class, "tx_" + TYPE_ASSETS_ISSUED);
		MESSAGE_COMMANDS.put(AssetsRegisterTransaction.class, "tx_" + TYPE_ASSETS_REGISTER);
		MESSAGE_COMMANDS.put(AssetsTransferTransaction.class, "tx_" + TYPE_ASSETS_TRANSFER);

		//===========================-分割线=============================//
		TRANSACTION_COMMANDS.add("tx_0");
		TRANSACTION_COMMANDS.add("tx_" + TYPE_REG_ALIAS);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_UPDATE_ALIAS);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_CERT_ACCOUNT_REGISTER);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_CERT_ACCOUNT_UPDATE);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_CERT_ACCOUNT_REVOKE);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_REG_CONSENSUS);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_REM_CONSENSUS);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_RELEVANCE_SUBACCOUNT);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_REMOVE_SUBACCOUNT);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_VIOLATION);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_CREDIT);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_ASSETS_ISSUED);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_ASSETS_REGISTER);
		TRANSACTION_COMMANDS.add("tx_" + TYPE_ASSETS_TRANSFER);

    	//===========================-分割线=============================//
    	
    	TRANSACTION_RELATION.put(TYPE_COINBASE, Transaction.class);
		TRANSACTION_RELATION.put(TYPE_PAY, Transaction.class);
		TRANSACTION_RELATION.put(TYPE_REG_ALIAS, RegAliasTransaction.class);
		TRANSACTION_RELATION.put(TYPE_UPDATE_ALIAS, UpdateAliasTransaction.class);
		TRANSACTION_RELATION.put(TYPE_REG_CONSENSUS, RegConsensusTransaction.class);
		TRANSACTION_RELATION.put(TYPE_REM_CONSENSUS, RemConsensusTransaction.class);
		TRANSACTION_RELATION.put(TYPE_CERT_ACCOUNT_REGISTER, CertAccountRegisterTransaction.class);
		TRANSACTION_RELATION.put(TYPE_CERT_ACCOUNT_UPDATE, CertAccountUpdateTransaction.class);
		TRANSACTION_RELATION.put(TYPE_CERT_ACCOUNT_REVOKE, CertAccountRevokeTransaction.class);
		TRANSACTION_RELATION.put(TYPE_RELEVANCE_SUBACCOUNT, RelevanceSubAccountTransaction.class);
		TRANSACTION_RELATION.put(TYPE_REMOVE_SUBACCOUNT, RemoveSubAccountTransaction.class);
		TRANSACTION_RELATION.put(TYPE_VIOLATION, ViolationTransaction.class);
		TRANSACTION_RELATION.put(TYPE_CREDIT, CreditTransaction.class);

		//资产相关
		TRANSACTION_RELATION.put(TYPE_ASSETS_REGISTER, AssetsRegisterTransaction.class);
		TRANSACTION_RELATION.put(TYPE_ASSETS_ISSUED, AssetsIssuedTransaction.class);
		TRANSACTION_RELATION.put(TYPE_ASSETS_TRANSFER, AssetsTransferTransaction.class);

    	//===========================-分割线=============================//
    	
    	for (Entry<Class<? extends Message>, String> entry : MESSAGE_COMMANDS.entrySet()) {
			COMMANDS_MESSAGE.put(entry.getValue(), entry.getKey());
		}
    }
}
