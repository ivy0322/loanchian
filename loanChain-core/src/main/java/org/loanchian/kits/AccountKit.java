package org.loanchian.kits;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;
import org.loanchian.Configure;
import org.loanchian.SpringContextUtils;
import org.loanchian.account.Account;
import org.loanchian.account.AccountBody;
import org.loanchian.account.AccountTool;
import org.loanchian.account.Address;
import org.loanchian.consensus.*;
import org.loanchian.core.*;
import org.loanchian.core.exception.MoneyNotEnoughException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.ECKey;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.filter.InventoryFilter;
import org.loanchian.listener.NoticeListener;
import org.loanchian.listener.TransactionListener;
import org.loanchian.mempool.MempoolContainer;
import org.loanchian.message.BlockHeader;
import org.loanchian.network.NetworkParams;
import org.loanchian.script.Script;
import org.loanchian.script.ScriptBuilder;
import org.loanchian.signers.LocalTransactionSigner;
import org.loanchian.store.*;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.TransactionInput;
import org.loanchian.transaction.TransactionOutput;
import org.loanchian.transaction.business.*;
import org.loanchian.utils.*;
import org.loanchian.validator.TransactionValidator;
import org.loanchian.validator.TransactionValidatorResult;
import org.loanchian.validator.ValidatorResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 账户管理
 * @author ln
 *
 */
@Service
public class AccountKit {

	private final static Logger log = LoggerFactory.getLogger(org.loanchian.kits.AccountKit.class);

	private final static Lock locker = new ReentrantLock();

	//账户文件路径
	private String accountDir;
	private List<Account> accountList = new ArrayList<Account>();
	//状态连存储服务
	@Autowired
	private ChainstateStoreProvider chainstateStoreProvider;
	//交易存储服务
	@Autowired
	private TransactionStoreProvider transactionStoreProvider;
	@Autowired
	private BlockStoreProvider blockStoreProvider;
	@Autowired
	private TransactionValidator transactionValidator;
	@Autowired
	private ConsensusPool consensusPool;
	//网络
	@Autowired
	private NetworkParams network;
	//节点管理器
	@Autowired
	private PeerKit peerKit;

	private long unlocktime;
	private boolean isLockWalletNow = true;
	private boolean isUnlockedByCmd = false;

	@Autowired
	private DataSynchronizeHandler dataSynchronizeHandler;

	//交易监听器
	private TransactionListener transactionListener;
	private TransactionValidatorResult rs;

	public AccountKit() throws IOException {
		//帐户信息保存于数据目录下的account目录，以account开始的dat文件，一个文件一个帐户，支持多帐户
		this.accountDir = Configure.DATA_ACCOUNT;

//		//初始化交易存储服务，保存与帐户有关的所有交易，保存于数据目录下的transaction文件夹
//		this.transactionStoreProvider = TransactionStoreProvider.getInstace(Configure.DATA_TRANSACTION, network);
//		//初始化状态链存储服务，该目录保存的所有未花费的交易，保存于数据目录下的chainstate文件夹
//		this.chainstateStoreProvider = TransactionStoreProvider.getInstace(Configure.DATA_CHAINSTATE, network);

	}

	/**
	 * 初始化账户信息
	 */
	public synchronized void init() throws IOException {
		maybeCreateAccountDir();
		loadAccount();
		initListeners();
	}

	/**
	 * 关闭资源
	 * @throws IOException
	 */
	public void close() throws IOException {
		chainstateStoreProvider.close();
	}

	/**
	 * 账户列表
	 */
	public void listAccount() {

	}

	/**
	 * 地址列表
	 */
	public void listAddress() {

	}

	/**
	 * 地址列表
	 */
	public void listAddress(String accountId) {

	}

	/**
	 * 获取默认账户
	 * @return Account
	 */
	public Account getDefaultAccount() {
		if(accountList == null || accountList.size() == 0) {
			return null;
		}
		return accountList.get(0);
	}

	/**
	 * 获取一个系统账户，如果没有则返回null
	 * @return Account
	 */
	public Account getSystemAccount() {
		if(accountList == null || accountList.size() == 0) {
			return null;
		}
		for (Account account : accountList) {
			if(!account.isCertAccount()) {
				return account;
			}
		}
		return null;
	}

	/**
	 * 获取一个认证账户，如果没有则返回null
	 * @return Account
	 */
	public Account getCertAccount() {
		if(accountList == null || accountList.size() == 0) {
			return null;
		}
		for (Account account : accountList) {
			if(account.isCertAccount()) {
				return account;
			}
		}
		return null;
	}

	/**
	 * 获取余额
	 */
	public Coin getBalance() {
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		return getBalance(getDefaultAccount());
	}

	/**
	 * 获取余额
	 */
	public Coin getBalance(String address) {
		return getBalance(Address.fromBase58(network, address));
	}

	/**
	 * 获取余额
	 */
	public Coin getBalance(Account account) {
		return getBalance(account.getAddress());
	}

	/**
	 * 获取余额
	 */
	public Coin getBalance(Address address) {
		if(address == null) {
			return Coin.ZERO;
		}
		return address.getBalance();
	}

	/**
	 * 获取可用余额
	 */
	public Coin getCanUseBalance() {
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		return getCanUseBalance(getDefaultAccount().getAddress());
	}

	/**
	 * 获取可用余额
	 */
	public Coin getCanUseBalance(String address) {
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		if(StringUtil.isEmpty(address)) {
			return getCanUseBalance();
		}
		for (Account account : accountList) {
			if(account.getAddress().getBase58().equals(address)) {
				return getCanUseBalance(account.getAddress());
			}
		}
		return Coin.ZERO;
	}

	/**
	 * 获取所有账户可用余额总数
	 */
	public Coin getTotalCanUseBalance() {
		Coin total = Coin.ZERO;
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		for (Account account : accountList) {
			total = total.add(getCanUseBalance(account.getAddress()));
		}
		return total;
	}



	/**
	 * 获取可用余额
	 */
	public Coin getCanUseBalance(Address address) {
		if(address == null) {
			return Coin.ZERO;
		}
		return address.getBalance();
	}

	/**
	 * 获取不可用余额
	 */
	public Coin getCanNotUseBalance() {
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		return getCanNotUseBalance(getDefaultAccount().getAddress());
	}

	/**
	 * 获取所有账户不可用总余额
	 */
	public Coin getTotalCanNotUseBalance() {
		Coin total = Coin.ZERO;
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		for (Account account : accountList) {
			total = total.add(getCanNotUseBalance(account.getAddress()));
		}
		return total;
	}

	/**
	 * 获取不可用余额
	 */
	public Coin getCanNotUseBalance(String address) {
		if(accountList == null || accountList.size() == 0) {
			return Coin.ZERO;
		}
		if(StringUtil.isEmpty(address)) {
			return getCanNotUseBalance();
		}
		for (Account account : accountList) {
			if(account.getAddress().getBase58().equals(address)) {
				return getCanNotUseBalance(account.getAddress());
			}
		}
		return Coin.ZERO;
	}

	/**
	 * 获取不可用余额
	 */
	public Coin getCanNotUseBalance(Address address) {
		if(address == null) {
			return Coin.ZERO;
		}
		return address.getUnconfirmedBalance();
	}


	/**
	 * 通过交易ID查询交易
	 * @param hash
	 * @return TransactionStore
	 */
	public TransactionStore getTransaction(Sha256Hash hash) {
		return blockStoreProvider.getTransaction(hash.getBytes());
	}

	/**
	 * 获取交易列表
	 */
	public List<TransactionStore> getTransactions() {
		return transactionStoreProvider.getTransactions();
	}

	/**
	 * 获取链上交易状态
	 */
	public byte[] getChainstate(byte[] hash) {
		return chainstateStoreProvider.getBytes(hash);
	}

	/**
	 * 获取交易列表
	 */
	public void getTransaction(String accountId) {

	}


	/**
	 * 锁仓指定数量的代币
	 * @param money	锁定金额
	 * @param money	锁定锁定是
	 * @return String
	 * @throws MoneyNotEnoughException
	 */
	public BroadcastResult lockMoney(Coin money, long lockTime, String address, String password, String remark) throws MoneyNotEnoughException {
		//参数不能为空

		locker.lock();
		try {
			//发送的金额必须大于100
			if(money.compareTo(Coin.COIN.multiply(100)) < 0) {
				throw new VerificationException("锁仓的金额需达到100");
			}
			//锁仓的时间必须大于24小时
			if(lockTime - TimeService.currentTimeSeconds() < 24 * 60 * 60) {
				throw new VerificationException("锁仓时间必须大于24小时");
			}
			if(accountList == null || accountList.size() == 0) {
				throw new VerificationException("没有可用账户");
			}

			//账户是否已加密
			Account account = null;

			if(StringUtil.isEmpty(address)) {
				account = getDefaultAccount();
			} else {
				account = getAccount(address);
			}

			if(account == null) {
				throw new VerificationException("地址不存在或错误");
			}

			if((account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) ||
					(account.getAccountType() == network.getCertAccountVersion() && account.isEncryptedOfTr())) {
				if(StringUtil.isEmpty(password)) {
					throw new VerificationException("账户已加密");
				}

				if(account.getAccountType() == network.getSystemAccountVersion()) {
					ECKey eckey = account.getEcKey().decrypt(password);
					account.setEcKey(eckey);
				} else {
					ECKey[] eckeys = account.decryptionTr(password);
					if(eckeys == null) {
						throw new VerificationException("密码错误");
					}
				}
			}

			//如果是认证账户，但是没有被收录进链里，则账户不可用
			if(account.isCertAccount() && account.getAccountTransaction() == null) {
				throw new VerificationException("账户不可用");
			}

			Address myAddress = account.getAddress();

			//当前余额可用余额
			Coin balance = myAddress.getBalance();

			//检查余额是否充足
			if(money.compareTo(balance) > 0) {
				throw new MoneyNotEnoughException("余额不足");
			}

			Transaction tx = new Transaction(network);
			tx.setLockTime(TimeService.currentTimeSeconds());
			tx.setType(Definition.TYPE_PAY);
			tx.setVersion(Definition.VERSION);
			tx.setRemark(null);

			Coin totalInputCoin = Coin.ZERO;

			//选择输入
			List<TransactionOutput> fromOutputs = selectNotSpentTransaction(money, myAddress);

			TransactionInput input = new TransactionInput();
			for (TransactionOutput output : fromOutputs) {
				input.addFrom(output);
				totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
			}
			//创建一个输入的空签名
			if(account.getAccountType() == network.getSystemAccountVersion()) {
				//普通账户的签名
				input.setScriptSig(ScriptBuilder.createInputScript(null, account.getEcKey()));
			} else {
				//认证账户的签名
				input.setScriptSig(ScriptBuilder.createCertAccountInputScript(null, account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160()));
			}
			tx.addInput(input);

			//交易输出
			tx.addOutput(money, lockTime, myAddress);
			//是否找零
			if(totalInputCoin.compareTo(money) > 0) {
				tx.addOutput(totalInputCoin.subtract(money), myAddress);
			}

			//签名交易
			final LocalTransactionSigner signer = new LocalTransactionSigner();
			try {
				if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					signer.signInputs(tx, account.getEcKey());
				} else {
					//认证账户的签名
					signer.signCertAccountInputs(tx, account.getTrEckeys(), account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160());
				}
			} catch (Exception e) {
				log.error(e.getMessage(), e);
				BroadcastResult broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("签名失败");
				return broadcastResult;
			}
			//验证交易是否合法
			ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx);
			if(!rs.getResult().isSuccess()) {
				throw new VerificationException(rs.getResult().getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			boolean success = MempoolContainer.getInstace().add(tx);
			transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));

			BroadcastResult broadcastResult = null;

			if(success) {
				//广播结果
				try {
					log.info("交易大小：{} , 输入数{} - {},  输出数 {} , hash {}", tx.baseSerialize().length, tx.getInputs().size(), tx.getInputs().get(0).getFroms().size(), tx.getOutputs().size(), tx.getHash());

					//等待广播回应
					broadcastResult = peerKit.broadcast(tx).get();

					//成功
					if(broadcastResult.isSuccess()) {
						//更新交易记录
						transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
					}
				} catch (Exception e) {
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("广播出错，"+e.getMessage());
				}
			} else {
				broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("重复的交易，禁止广播");
			}
			return broadcastResult;
		} finally {
			locker.unlock();
		}
	}

	/**
	 * 发送普通交易到指定地址
	 * @param to   base58的地址
	 * @param money	发送金额
	 * @param fee	手续费
	 * @return String
	 * @throws MoneyNotEnoughException
	 */
	public BroadcastResult sendMoney(String to, Coin money, Coin fee) throws MoneyNotEnoughException {
		return sendMoney(to, money, fee, null, null, null);
	}

	/**
	 * 发送普通交易到指定地址
	 * @param to   base58的地址
	 * @param money	发送金额
	 * @param fee	手续费
	 * @return String
	 * @throws MoneyNotEnoughException
	 */
	public BroadcastResult sendMoney(String to, Coin money, Coin fee, byte[] remark, String address, String password) throws MoneyNotEnoughException {
		//参数不能为空
		Utils.checkNotNull(to);
		long bestheight = 0;
		long localbestheighttime = 0;

		bestheight = network.getBestHeight();
		localbestheighttime = blockStoreProvider.getBestBlockHeader().getBlockHeader().getTime();
		if(peerKit.getAvailablePeersCount()==0){
			throw new VerificationException("当前网络不可用，请稍后再尝试");
		}

		if(bestheight == 0){
			if(dataSynchronizeHandler.isDownloading()) {
				throw new VerificationException("正在同步区块中，请稍后再尝试");
			}else {
				peerKit.resetPeers();
				dataSynchronizeHandler.reset();
				dataSynchronizeHandler.run();
				throw new VerificationException("当前网络不可用，正在重试网络和数据修复，请稍后再尝试");
			}
		}
		if(TimeService.currentTimeSeconds()-localbestheighttime>60){
			if(dataSynchronizeHandler.isDownloading()) {
				throw new VerificationException("正在同步区块中，请稍后再尝试");
			}else {
				peerKit.resetPeers();
				dataSynchronizeHandler.reset();
				dataSynchronizeHandler.run();
				throw new VerificationException("当前网络不可用，正在重试网络和数据修复，请稍后再尝试");
			}
		}



		locker.lock();
		try {
			Address receiveAddress = null;
			try {
				receiveAddress = Address.fromBase58(network, to);
			} catch (Exception e) {
				throw new VerificationException("错误的接收地址");
			}

			//发送的金额必须大于0
			if(money.compareTo(Coin.ZERO) <= 0) {
				throw new RuntimeException("发送的金额需大于0");
			}
			if(fee == null || fee.compareTo(Coin.ZERO) < 0) {
				fee = Definition.MIN_PAY_FEE;
			}

			if(accountList == null || accountList.size() == 0) {
				throw new VerificationException("没有可用账户");
			}

			//账户是否已加密
			Account account = null;

			if(StringUtil.isEmpty(address)) {
				account = getDefaultAccount();
			} else {
				account = getAccount(address);
			}

			if(account == null) {
				throw new VerificationException("地址不存在或错误");
			}

			//不能给自己转账
			if(Arrays.equals(receiveAddress.getHash160(), account.getAddress().getHash160())) {
				throw new VerificationException("不能给自己转账");
			}

			if((account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) ||
					(account.getAccountType() == network.getCertAccountVersion() && account.isEncryptedOfTr())) {
				if(StringUtil.isEmpty(password)) {
					throw new VerificationException("账户已加密");
				}

				if(account.getAccountType() == network.getSystemAccountVersion()) {
					ECKey eckey = account.getEcKey().decrypt(password);
					account.setEcKey(eckey);
				} else {
					ECKey[] eckeys = account.decryptionTr(password);
					if(eckeys == null) {
						throw new VerificationException("密码错误");
					}
				}
			}

			//如果是认证账户，但是没有被收录进链里，则账户不可用
			if(account.isCertAccount() && account.getAccountTransaction() == null) {
				throw new VerificationException("账户不可用");
			}

			Address myAddress = account.getAddress();

			//当前余额可用余额
			Coin balance = myAddress.getBalance();

			//检查余额是否充足
			if(money.add(fee).compareTo(balance) > 0) {
				throw new MoneyNotEnoughException("余额不足");
			}

			Transaction tx = new Transaction(network);
			tx.setLockTime(TimeService.currentTimeSeconds());
			tx.setType(Definition.TYPE_PAY);
			tx.setVersion(Definition.VERSION);
			tx.setRemark(remark);

			Coin totalInputCoin = Coin.ZERO;

			//选择输入
			List<TransactionOutput> fromOutputs = selectNotSpentTransaction(money.add(fee), myAddress);

			TransactionInput input = new TransactionInput();
			for (TransactionOutput output : fromOutputs) {
				input.addFrom(output);
				totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
			}
			//创建一个输入的空签名
			if(account.getAccountType() == network.getSystemAccountVersion()) {
				//普通账户的签名
				input.setScriptSig(ScriptBuilder.createInputScript(null, account.getEcKey()));
			} else {
				//认证账户的签名
				input.setScriptSig(ScriptBuilder.createCertAccountInputScript(null, account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160()));
			}
			tx.addInput(input);

			//交易输出
			tx.addOutput(money, receiveAddress);
			//是否找零
			if(totalInputCoin.compareTo(money.add(fee)) > 0) {
				tx.addOutput(totalInputCoin.subtract(money.add(fee)), myAddress);
			}

			//签名交易
			final LocalTransactionSigner signer = new LocalTransactionSigner();
			try {
				if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					signer.signInputs(tx, account.getEcKey());
				} else {
					//认证账户的签名
					signer.signCertAccountInputs(tx, account.getTrEckeys(), account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160());
				}
			} catch (Exception e) {
				log.error(e.getMessage(), e);
				BroadcastResult broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("签名失败");
				return broadcastResult;
			}
			//验证交易是否合法
			ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx);
			if(!rs.getResult().isSuccess()) {
				throw new VerificationException(rs.getResult().getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			boolean success = MempoolContainer.getInstace().add(tx);

			BroadcastResult broadcastResult = null;

			if(success) {
				transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
				//广播结果
				try {
					log.info("交易大小：{} , 输入数{} - {},  输出数 {} , hash {}", tx.baseSerialize().length, tx.getInputs().size(), tx.getInputs().get(0).getFroms().size(), tx.getOutputs().size(), tx.getHash());
					//等待广播回应
					broadcastResult = peerKit.broadcast(tx).get();
					//成功
					if(broadcastResult.isSuccess()) {
						//更新交易记录
						transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
					}
				} catch (Exception e) {
					e.printStackTrace();
					broadcastResult = new BroadcastResult();
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("广播出错，"+e.getMessage());
				}
			} else {
				broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("重复的交易，禁止广播");
			}
			return broadcastResult;
		} finally {
			locker.unlock();
		}
	}

	/**
	 * 发送普通交易到指定地址
	 * @param toaddressAndCoins   base58的地址
	 * @param fee	手续费
	 * @param pass
	 * @return remark
	 * @throws MoneyNotEnoughException
	 */
	public BroadcastResult sendtoAddress(JSONArray toaddressAndCoins, Coin fee,String pass, byte[] remark) throws MoneyNotEnoughException {
		BroadcastResult result = new BroadcastResult();
		Coin moneyCoin = Coin.ZERO;
		Coin feeCoin = fee;
		String tmpAddress = null;
		Coin tmpCoin = null;
		List <TransactionOutput> outputList = new ArrayList<TransactionOutput>();
		try {
			for(int index=0;index<toaddressAndCoins.length();index++){
				JSONObject toaddressAndCoin = toaddressAndCoins.getJSONObject(index);
				Iterator<String> keyIt = toaddressAndCoin.keys();
				while(keyIt.hasNext()) {
					tmpAddress = keyIt.next();
					try{
						Address.fromBase58(network,tmpAddress);
					}catch (Exception e){
							result.setSuccess(false);
							result.setMessage("接收地址不合法");
							return result;
					}
					if((getAccount(tmpAddress)!=null)) {
						result.setSuccess(false);
						result.setMessage("不能转账给自己");
						return result;
					}
					try {
						tmpCoin  = Coin.parseCoin(toaddressAndCoin.getString(tmpAddress));
					}catch (Exception e){
						result.setSuccess(false);
						result.setMessage("转账金额不合法");
						return result;
					}
					moneyCoin = moneyCoin.add(tmpCoin);
				}
				outputList.add(new TransactionOutput(null,tmpCoin,Address.fromBase58(network,tmpAddress)));
			}

			Coin total = getTotalCanUseBalance();
			if(total.isLessThan(moneyCoin.add(feeCoin))){
				result.setSuccess( false);
				result.setMessage("总余额不足");
				return result;
			}
		}catch (Exception e){
			result.setSuccess( false);
			result.setMessage("参数错误");
			return result;
		}

		long bestheight = 0;
		long localbestheighttime = 0;

		bestheight = network.getBestHeight();
		localbestheighttime = blockStoreProvider.getBestBlockHeader().getBlockHeader().getTime();
		if(bestheight == 0){
			if(dataSynchronizeHandler.isDownloading()) {
				throw new VerificationException("正在同步区块中，请稍后再尝试");
			}else {
				peerKit.resetPeers();
				dataSynchronizeHandler.reset();
				dataSynchronizeHandler.run();
				throw new VerificationException("当前网络不可用，正在重试网络和数据修复，请稍后再尝试");
			}
		}
		if(TimeService.currentTimeSeconds()-localbestheighttime>60){
			if(dataSynchronizeHandler.isDownloading()) {
				throw new VerificationException("正在同步区块中，请稍后再尝试");
			}else {
				peerKit.resetPeers();
				dataSynchronizeHandler.reset();
				dataSynchronizeHandler.run();
				throw new VerificationException("当前网络不可用，正在重试网络和数据修复，请稍后再尝试");
			}
		}

		boolean isEnctypted=false;
		for(Account account:accountList){
			if(!account.isCertAccount()&&account.isEncrypted()){
				if(pass == null){
					throw new VerificationException("账户已加密，未传入密码");
				}
				Result rs = decryptAccount(pass,account.getAddress().getBase58());
				if(!rs.isSuccess())
					throw new VerificationException("账户已加密，密码错误");
				isEnctypted =true;
			}
		}

		if(!isEnctypted) {
			if(remark == null && pass!=null)
				remark=pass.getBytes();
		}

		locker.lock();
		try {

			if(fee == null || fee.compareTo(Coin.ZERO) < 0) {
				fee = Definition.MIN_PAY_FEE;
			}

			if(accountList == null || accountList.size() == 0) {
				throw new VerificationException("没有可用账户");
			}

			Transaction tx = new Transaction(network);
			tx.setLockTime(TimeService.currentTimeSeconds());
			tx.setType(Definition.TYPE_PAY);
			tx.setVersion(Definition.VERSION);
			tx.setRemark(remark);

			Coin totalInputCoin = Coin.ZERO;

			//选择输入
			List<Address> addresses= new ArrayList<Address>();
			for (int j=0;j<accountList.size();j++){
				addresses.add(accountList.get(j).getAddress());
			}

			HashMap<String,List<TransactionOutput>> fromOutputs = selectNotSpentTransaction(moneyCoin.add(fee), addresses);
			List<Account> signAccounts = new ArrayList<Account>();

			Iterator it = fromOutputs.keySet().iterator();
			while (it.hasNext()){
				TransactionInput input = new TransactionInput();
				String address = (String) it.next();
				List<TransactionOutput> userOutput = fromOutputs.get(address);
				for (TransactionOutput output : userOutput) {
					input.addFrom(output);
					totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
				}

				Account account = getAccount(address);
				signAccounts.add(account);
				//创建一个输入的空签名
				if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					input.setScriptSig(ScriptBuilder.createInputScript(null, account.getEcKey()));
				} else {
					//认证账户的签名
					input.setScriptSig(ScriptBuilder.createCertAccountInputScript(null, account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160()));
				}
				tx.addInput(input);

			}
			//交易输出
			for(TransactionOutput output:outputList) {
				tx.addOutput(output);
			}
			//是否找零

			if(totalInputCoin.compareTo(moneyCoin.add(fee)) > 0) {
				tx.addOutput(totalInputCoin.subtract(moneyCoin.add(fee)), signAccounts.get(0).getAddress());
			}

			//签名交易
			final LocalTransactionSigner signer = new LocalTransactionSigner();
			for(int i =0;i<signAccounts.size();i++) {
				try {
					//if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					signer.signOneInputs(tx, signAccounts.get(i).getEcKey(),i);
					//} else {
					//认证账户的签名
					//	signer.signCertAccountInputs(tx, account.getTrEckeys(), account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160());
					//}
				} catch (Exception e) {
					log.error(e.getMessage(), e);
					BroadcastResult broadcastResult = new BroadcastResult();
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("签名失败");
					return broadcastResult;
				}
			}
			//验证交易是否合法
			ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx);
			if(!rs.getResult().isSuccess()) {
				throw new VerificationException(rs.getResult().getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			boolean success = MempoolContainer.getInstace().add(tx);

			BroadcastResult broadcastResult = null;

			if(success) {
				transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
				//广播结果
				try {
					log.info("交易大小：{} , 输入数{} - {},  输出数 {} , hash {}", tx.baseSerialize().length, tx.getInputs().size(), tx.getInputs().get(0).getFroms().size(), tx.getOutputs().size(), tx.getHash());
					//等待广播回应
					broadcastResult = peerKit.broadcast(tx).get();
					//成功
					if(broadcastResult.isSuccess()) {
						//更新交易记录
						transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
					}
				} catch (Exception e) {
					e.printStackTrace();
					broadcastResult = new BroadcastResult();
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("广播出错，"+e.getMessage());
				}
			} else {
				broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("重复的交易，禁止广播");
			}
			return broadcastResult;
		} finally {
			locker.unlock();
		}
	}



	/**
	 * 发送普通交易到指定地址
	 * @param to   base58的地址
	 * @param money	发送金额
	 * @param fee	手续费
	 * @return String
	 * @throws MoneyNotEnoughException
	 */
	public BroadcastResult sendLockMoney(String to, Coin money, Coin fee, byte[] remark, String address, String password, long lockTime) throws MoneyNotEnoughException {
		//参数不能为空
		Utils.checkNotNull(to);
		long bestheight = 0;
		long localheight = 0;
		long localbestheighttime = 0;

		bestheight = network.getBestHeight();
		localheight = blockStoreProvider.getBestBlockHeader().getBlockHeader().getHeight();
		localbestheighttime = blockStoreProvider.getBestBlockHeader().getBlockHeader().getTime();
		if(bestheight == 0){
			if(dataSynchronizeHandler.isDownloading()) {
				throw new VerificationException("正在同步区块中，请稍后再尝试");
			}else {
				peerKit.resetPeers();
				dataSynchronizeHandler.reset();
				dataSynchronizeHandler.run();
				throw new VerificationException("当前网络不可用，正在重试网络和数据修复，请稍后再尝试");
			}
		}
		if(TimeService.currentTimeSeconds()-localbestheighttime>60){
			if(dataSynchronizeHandler.isDownloading()) {
				throw new VerificationException("正在同步区块中，请稍后再尝试");
			}else {
				peerKit.resetPeers();
				dataSynchronizeHandler.reset();
				dataSynchronizeHandler.run();
				throw new VerificationException("当前网络不可用，正在重试网络和数据修复，请稍后再尝试");
			}
		}

		locker.lock();
		try {
			Address receiveAddress = null;
			try {
				receiveAddress = Address.fromBase58(network, to);
			} catch (Exception e) {
				throw new VerificationException("错误的接收地址");
			}

			//发送的金额必须大于0
			if(money.compareTo(Coin.ZERO) <= 0) {
				throw new RuntimeException("发送的金额需大于0");
			}
			if(fee == null || fee.compareTo(Coin.ZERO) < 0) {
				fee = Definition.MIN_PAY_FEE;
			}

			if(accountList == null || accountList.size() == 0) {
				throw new VerificationException("没有可用账户");
			}

			//账户是否已加密
			Account account = null;

			if(StringUtil.isEmpty(address)) {
				account = getDefaultAccount();
			} else {
				account = getAccount(address);
			}

			if(account == null) {
				throw new VerificationException("地址不存在或错误");
			}

			//不能给自己转账
			if(Arrays.equals(receiveAddress.getHash160(), account.getAddress().getHash160())) {
				throw new VerificationException("不能给自己转账");
			}

			if((account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) ||
					(account.getAccountType() == network.getCertAccountVersion() && account.isEncryptedOfTr())) {
				if(StringUtil.isEmpty(password)) {
					throw new VerificationException("账户已加密");
				}

				if(account.getAccountType() == network.getSystemAccountVersion()) {
					ECKey eckey = account.getEcKey().decrypt(password);
					account.setEcKey(eckey);
				} else {
					ECKey[] eckeys = account.decryptionTr(password);
					if(eckeys == null) {
						throw new VerificationException("密码错误");
					}
				}
			}

			//如果是认证账户，但是没有被收录进链里，则账户不可用
			if(account.isCertAccount() && account.getAccountTransaction() == null) {
				throw new VerificationException("账户不可用");
			}

			Address myAddress = account.getAddress();

			//当前余额可用余额
			Coin balance = myAddress.getBalance();

			//检查余额是否充足
			if(money.add(fee).compareTo(balance) > 0) {
				throw new MoneyNotEnoughException("余额不足");
			}

			Transaction tx = new Transaction(network);
			tx.setLockTime(TimeService.currentTimeSeconds());
			tx.setType(Definition.TYPE_PAY);
			tx.setVersion(Definition.VERSION);
			tx.setRemark(remark);

			Coin totalInputCoin = Coin.ZERO;

			//选择输入
			List<TransactionOutput> fromOutputs = selectNotSpentTransaction(money.add(fee), myAddress);

			TransactionInput input = new TransactionInput();
			for (TransactionOutput output : fromOutputs) {
				input.addFrom(output);
				totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
			}
			//创建一个输入的空签名
			if(account.getAccountType() == network.getSystemAccountVersion()) {
				//普通账户的签名
				input.setScriptSig(ScriptBuilder.createInputScript(null, account.getEcKey()));
			} else {
				//认证账户的签名
				input.setScriptSig(ScriptBuilder.createCertAccountInputScript(null, account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160()));
			}
			tx.addInput(input);

			//交易输出
			tx.addOutput(money, lockTime, receiveAddress);
			//是否找零
			if(totalInputCoin.compareTo(money.add(fee)) > 0) {
				tx.addOutput(totalInputCoin.subtract(money.add(fee)), myAddress);
			}

			//签名交易
			final LocalTransactionSigner signer = new LocalTransactionSigner();
			try {
				if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					signer.signInputs(tx, account.getEcKey());
				} else {
					//认证账户的签名
					signer.signCertAccountInputs(tx, account.getTrEckeys(), account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160());
				}
			} catch (Exception e) {
				log.error(e.getMessage(), e);
				BroadcastResult broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("签名失败");
				return broadcastResult;
			}
			//验证交易是否合法
			ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx);
			if(!rs.getResult().isSuccess()) {
				throw new VerificationException(rs.getResult().getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			boolean success = MempoolContainer.getInstace().add(tx);

			BroadcastResult broadcastResult = null;

			if(success) {
				transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
				//广播结果
				try {
					log.info("交易大小：{} , 输入数{} - {},  输出数 {} , hash {}", tx.baseSerialize().length, tx.getInputs().size(), tx.getInputs().get(0).getFroms().size(), tx.getOutputs().size(), tx.getHash());
					//等待广播回应
					broadcastResult = peerKit.broadcast(tx).get();
					//成功
					if(broadcastResult.isSuccess()) {
						//更新交易记录
						transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
					}
				} catch (Exception e) {
					e.printStackTrace();
					broadcastResult = new BroadcastResult();
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("广播出错，"+e.getMessage());
				}
			} else {
				broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("重复的交易，禁止广播");
			}
			return broadcastResult;
		} finally {
			locker.unlock();
		}
	}

	/**
	 * 广播交易
	 * @param myAccount
	 * @param moneyCoin
	 * @param feeCoin
	 * @param fromOutputs
	 * @param receiveAddress
	 * @return
	 */
	public BroadcastResult broadcastTransferTransaction(Account myAccount, Coin moneyCoin, Coin feeCoin,
														List<TransactionOutput> fromOutputs, Address receiveAddress,String remark) {
		locker.lock();

		try {
			Transaction tx = new Transaction(network);
			tx.setLockTime(TimeService.currentTimeSeconds());
			tx.setType(Definition.TYPE_PAY);
			tx.setVersion(Definition.VERSION);
			tx.setRemark(remark.getBytes("utf-8"));
			//输入金额
			Coin totalInputCoin = Coin.ZERO;
			TransactionInput input = new TransactionInput();
			for (TransactionOutput output : fromOutputs) {
				input.addFrom(output);
				totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
			}

			//普通账户的签名
			input.setScriptSig(ScriptBuilder.createInputScript(null, myAccount.getEcKey()));
			tx.addInput(input);

			//交易输出
			tx.addOutput(moneyCoin, receiveAddress);
			//是否找零
			if(totalInputCoin.compareTo(moneyCoin.add(feeCoin)) > 0) {
				tx.addOutput(totalInputCoin.subtract(moneyCoin.add(feeCoin)), myAccount.getAddress());
			}else if(totalInputCoin.compareTo(moneyCoin.add(feeCoin)) < 0) {
				throw new VerificationException("用户余额不足");
			}

			//签名交易
			final LocalTransactionSigner signer = new LocalTransactionSigner();
			try {
				//普通账户的签名
				signer.signInputs(tx, myAccount.getEcKey());
			} catch (Exception e) {
				log.error(e.getMessage(), e);
				throw new VerificationException("交易签名失败，请检查账户类型");
			}

			//验证交易是否合法
			ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx);
			if(!rs.getResult().isSuccess()) {
				throw new VerificationException(rs.getResult().getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			boolean success = MempoolContainer.getInstace().add(tx);
			BroadcastResult broadcastResult = null;

			if(success) {
				transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
				//广播结果
				try {
					log.info("交易大小：{} , 输入数{} - {},  输出数 {} , hash {}", tx.baseSerialize().length, tx.getInputs().size(), tx.getInputs().get(0).getFroms().size(), tx.getOutputs().size(), tx.getHash());
					//等待广播回应
					broadcastResult = peerKit.broadcast(tx).get();
					//成功
					if(broadcastResult.isSuccess()) {
						//更新交易记录
						transactionStoreProvider.processNewTransaction(new TransactionStore(network, tx));
					}
				} catch (Exception e) {
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("广播出错，"+e.getMessage());
					MempoolContainer.getInstace().remove(tx.getHash());
				}
			} else {
				broadcastResult = new BroadcastResult();
				broadcastResult.setSuccess(false);
				broadcastResult.setMessage("重复的交易，禁止广播");
			}

			return broadcastResult;
		}catch (Exception e) {
			throw new VerificationException(e.getMessage());
		}finally {
			locker.unlock();
		}
	}

	/**
	 * 发送普通交易到指定地址
	 * @param to   base58的地址
	 * @param money	发送金额
	 * @param fee	手续费
	 * @return String
	 * @throws MoneyNotEnoughException
	 */
	//测试方法，将来会删掉的
	public BroadcastResult sendMoney1(String to, Coin money, Coin fee, byte[] remark, String address, String password) throws MoneyNotEnoughException {
		//参数不能为空
		Utils.checkNotNull(to);

		locker.lock();
		try {
			List<Transaction> txList = new ArrayList<Transaction>();

			long now = System.currentTimeMillis();

			Address receiveAddress = null;
			try {
				receiveAddress = Address.fromBase58(network, to);
			} catch (Exception e) {
				throw new VerificationException("错误的接收地址");
			}

			//发送的金额必须大于0
			if(money.compareTo(Coin.ZERO) <= 0) {
				throw new RuntimeException("发送的金额需大于0");
			}

			if(fee == null || fee.compareTo(Coin.ZERO) < 0) {
				fee = Coin.ZERO;
			}

			if(accountList == null || accountList.size() == 0) {
				throw new VerificationException("没有可用账户");
			}

			for (int i = 0; i < 20000; i++) {

				//账户是否已加密
				Account account = null;

				if(StringUtil.isEmpty(address)) {
					account = getDefaultAccount();
				} else {
					account = getAccount(address);
				}

				if(account == null) {
					throw new VerificationException("地址不存在或错误");
				}

				if((account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) ||
						(account.getAccountType() == network.getCertAccountVersion() && account.isEncryptedOfTr())) {
					if(StringUtil.isEmpty(password)) {
						throw new VerificationException("账户已加密");
					}

					if(account.getAccountType() == network.getSystemAccountVersion()) {
						ECKey eckey = account.getEcKey().decrypt(password);
						account.setEcKey(eckey);
					} else {
						ECKey[] eckeys = account.decryptionTr(password);
						if(eckeys == null) {
							throw new VerificationException("密码错误");
						}
					}
				}

				//如果是认证账户，但是没有被收录进链里，则账户不可用
				if(account.isCertAccount() && account.getAccountTransaction() == null) {
					throw new VerificationException("账户不可用");
				}

				Address myAddress = account.getAddress();

				//当前余额可用余额
				Coin balance = myAddress.getBalance();

				//检查余额是否充足
				if(money.add(fee).compareTo(balance) > 0) {
					throw new MoneyNotEnoughException("余额不足");
				}

				Transaction tx = new Transaction(network);
				tx.setLockTime(TimeService.currentTimeSeconds());
				tx.setType(Definition.TYPE_PAY);
				tx.setVersion(Definition.VERSION);
				tx.setRemark(remark);

				Coin totalInputCoin = Coin.ZERO;

				TransactionInput input = new TransactionInput();

				if(i == 0) {
					//选择输入
					List<TransactionOutput> fromOutputs = selectNotSpentTransaction(money.add(fee), myAddress);

					for (TransactionOutput output : fromOutputs) {
						input.addFrom(output);
						totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
					}
				} else {
					TransactionOutput output = txList.get(txList.size() - 1).getOutput(1);
					input.addFrom(output);
					totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
				}
				//创建一个输入的空签名
				if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					input.setScriptSig(ScriptBuilder.createInputScript(null, account.getEcKey()));
				} else {
					//认证账户的签名
					input.setScriptSig(ScriptBuilder.createCertAccountInputScript(null, account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160()));
				}
				tx.addInput(input);

				//交易输出
				tx.addOutput(money, receiveAddress);
				//是否找零
				if(totalInputCoin.compareTo(money.add(fee)) > 0) {
					tx.addOutput(totalInputCoin.subtract(money.add(fee)), myAddress);
				}

				//签名交易
				final LocalTransactionSigner signer = new LocalTransactionSigner();
				try {
					if(account.getAccountType() == network.getSystemAccountVersion()) {
						//普通账户的签名
						signer.signInputs(tx, account.getEcKey());
					} else {
						//认证账户的签名
						signer.signCertAccountInputs(tx, account.getTrEckeys(), account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160());
					}
				} catch (Exception e) {
					log.error(e.getMessage(), e);
					BroadcastResult broadcastResult = new BroadcastResult();
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("签名失败");
					return broadcastResult;
				}
				//验证交易是否合法
				ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx);
				if(!rs.getResult().isSuccess()) {
					throw new VerificationException(rs.getResult().getMessage());
				}

				//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
				boolean success = MempoolContainer.getInstace().add(tx);
				txList.add(tx);
			}
			System.out.println("构建交易耗时："+(System.currentTimeMillis() - now)+"ms");
			now = System.currentTimeMillis();

			InventoryFilter filter = SpringContextUtils.getBean(InventoryFilter.class);
			for (Transaction transaction : txList) {
				peerKit.broadcastMessage(transaction);
				filter.insert(transaction.getHash().getBytes());
			}
			System.out.println("广播耗时："+(System.currentTimeMillis() - now)+"ms, 成功广播" +txList.size()+"条交易");

			return new BroadcastResult(true, "成功");
		} finally {
			locker.unlock();
		}
	}

	/*
	 * 获取交易的手续费
	 */
	private Coin getTransactionFee(Transaction tx) {
		Coin inputFee = Coin.ZERO;

		List<TransactionInput> inputs = tx.getInputs();
		for (TransactionInput input : inputs) {
			if(input.getFroms() == null || input.getFroms().size() ==0) {
				continue;
			}
			for (TransactionOutput from : input.getFroms()) {
				inputFee = inputFee.add(Coin.valueOf(from.getValue()));
			}
		}

		Coin outputFee = Coin.ZERO;
		List<TransactionOutput> outputs = tx.getOutputs();
		for (TransactionOutput output : outputs) {
			outputFee = outputFee.add(Coin.valueOf(output.getValue()));
		}
		return inputFee.subtract(outputFee);
	}

	/**
	 * 交易选择
	 * 查找并返回最接近该金额的未花费的交易
	 * @param amount 金额
	 * @param address 账户地址
	 * @return List<TransactionOutput>
	 */
	public List<TransactionOutput> selectNotSpentTransaction(Coin amount, Address address) {

		//获取到所有未花费的交易
		List<TransactionOutput> outputs = transactionStoreProvider.getNotSpentTransactionOutputs(address.getHash160());

		//选择结果存放列表
		List<TransactionOutput> thisOutputs = new ArrayList<TransactionOutput>();

		if(outputs == null || outputs.size() == 0) {
			return thisOutputs;
		}

		//遍历选择，原则是尽量少的数据，也就是笔数最少

		//小于amount的集合
		List<TransactionOutput> lessThanList = new ArrayList<TransactionOutput>();
		//大于amount的集合
		List<TransactionOutput> moreThanList = new ArrayList<TransactionOutput>();

		for (TransactionOutput transactionOutput : outputs) {
			if(transactionOutput.getValue() == amount.value) {
				//如果刚好相等，则立即返回
				thisOutputs.add(transactionOutput);
				return thisOutputs;
			} else if(transactionOutput.getValue() > amount.value) {
				//加入大于集合
				moreThanList.add(transactionOutput);
			} else {
				//加入小于于集合
				lessThanList.add(transactionOutput);
			}
		}

		if(Configure.TRANSFER_PREFERRED == 2) {
			//优先使用零钱
			transferPreferredWithSmallChange(amount, lessThanList, moreThanList, thisOutputs);
		} else {
			//以交易数据小优先，该种机制尽量选择一笔输入，默认方式
			transferPreferredWithLessNumber(amount, lessThanList, moreThanList, thisOutputs);
		}
		//依然按照交易时间排序
		if(thisOutputs.size() > 0) {
			Collections.sort(thisOutputs, new Comparator<TransactionOutput>() {
				@Override
				public int compare(TransactionOutput o1, TransactionOutput o2) {
					long v1 = o1.getParent().getTime();
					long v2 = o2.getParent().getTime();
					if(v1 == v2) {
						return 0;
					} else if(v1 > v2) {
						return 1;
					} else {
						return -1;
					}
				}
			});
		}
		return thisOutputs;
	}

	public HashMap<String,List<TransactionOutput>> selectNotSpentTransaction(Coin amount, List<Address>  addresses) {

		List <byte[]> hash160s =new ArrayList<byte[]>();
		for(int i=0;i<addresses.size();i++){
			hash160s.add(addresses.get(i).getHash160());
		}

		//获取到所有未花费的交易
		HashMap<String,List<TransactionOutput>> outputs = transactionStoreProvider.getNotSpentTransactionOutputs(hash160s);

		//选择结果存放列表
		HashMap<String,List<TransactionOutput>> thisOutputs = new HashMap<String,List<TransactionOutput>>();

		if(outputs == null || outputs.size() == 0) {
			return thisOutputs;
		}

		//遍历选择，原则是尽量少的数据，也就是笔数最少

		//小于amount的集合
		HashMap<String,List<TransactionOutput>> lessThanList = new HashMap<String,List<TransactionOutput>>();
		//大于amount的集合
		HashMap<String,List<TransactionOutput>> moreThanList = new HashMap<String,List<TransactionOutput>>();

		Iterator <String> it = outputs.keySet().iterator();
		while (it.hasNext()) {
			String address = it.next();
			List<TransactionOutput> userOutput = outputs.get(address);
			List<TransactionOutput> userLessThanList = new ArrayList<TransactionOutput>();
			List<TransactionOutput> userMoreThanList = new ArrayList<TransactionOutput>();
			for (TransactionOutput transactionOutput : userOutput) {
				if (transactionOutput.getValue() == amount.value) {
					//如果刚好相等，则立即返回
					HashMap<String,List<TransactionOutput>> returnMap=new HashMap<String,List<TransactionOutput>>();
					List<TransactionOutput> returnList=new ArrayList<TransactionOutput>();
					returnList.add(transactionOutput);
					returnMap.put(address,returnList);
					return returnMap;
				} else if (transactionOutput.getValue() > amount.value) {
					//加入大于集合
					userMoreThanList.add(transactionOutput);
				} else {
					//加入小于于集合
					userLessThanList.add(transactionOutput);
				}
			}
			moreThanList.put(address,userMoreThanList);
			lessThanList.put(address,userLessThanList);
		}

		if(Configure.TRANSFER_PREFERRED == 2) {
			//优先使用零钱
			transferPreferredWithSmallChangeMulUser(amount, lessThanList, moreThanList, thisOutputs);
		} else {
			//以交易数据小优先，该种机制尽量选择一笔输入，默认方式
			transferPreferredWithLessNumberMulUser(amount, lessThanList, moreThanList, thisOutputs);
		}
		Set nullset = new HashSet<String>();
		it = thisOutputs.keySet().iterator();
		while (it.hasNext()) {
			String address = it.next();
			List <TransactionOutput> userOutputs = thisOutputs.get(address);
			if(userOutputs.size()==0)
				nullset.add(address);
		}
		it = nullset.iterator();
		while (it.hasNext()){
			String address= it.next();
			thisOutputs.remove(address);
		}
		return thisOutputs;
	}

	/*
	 * 交易选择 -- 优先使用零钱
	 */
	private void transferPreferredWithSmallChange(Coin amount, List<TransactionOutput> lessThanList,
												  List<TransactionOutput> moreThanList, List<TransactionOutput> thisOutputs) {
		if(lessThanList.size() > 0) {
			//计算所有零钱，是否足够
			Coin lessTotal = Coin.ZERO;
			for (TransactionOutput transactionOutput : lessThanList) {
				lessTotal = lessTotal.add(Coin.valueOf(transactionOutput.getValue()));
			}

			if(lessTotal.isLessThan(amount)) {
				//不够，那么必定有大的
				selectOneOutput(moreThanList, thisOutputs);
			} else {
				//选择零钱
				selectSmallChange(amount, lessThanList, thisOutputs);
			}
		} else {
			//没有比本次交易最大的未输出交易
			selectOneOutput(moreThanList, thisOutputs);
		}
	}

	/*
	 * 交易选择 -- 优先使用零钱
	 */
	private void transferPreferredWithSmallChangeMulUser(Coin amount, HashMap<String, List<TransactionOutput>> lessThanList,
														 HashMap<String, List<TransactionOutput>> moreThanList, HashMap<String, List<TransactionOutput>> thisOutputs) {
		if(lessThanList.size() > 0) {
			//计算所有零钱，是否足够
			Coin lessTotal = Coin.ZERO;
			Iterator<String> lessit= lessThanList.keySet().iterator();
			while (lessit.hasNext()){
				String address = lessit.next();
				List<TransactionOutput> userLessThanlist = lessThanList.get(address);
				for (TransactionOutput transactionOutput : userLessThanlist) {
					lessTotal = lessTotal.add(Coin.valueOf(transactionOutput.getValue()));
				}
			}

			if(lessTotal.isLessThan(amount)) {
				//不够，那么必定有大的
				selectOneOutputMulUser(moreThanList, thisOutputs);
			} else {
				//选择零钱
				selectSmallChangeMulUser(amount, lessThanList, thisOutputs);
			}
		} else {
			//没有比本次交易最大的未输出交易
			selectOneOutputMulUser(moreThanList, thisOutputs);
		}
	}

	/*
	 * 交易选择 -- 以交易数据小优先，该种机制尽量选择一笔输入
	 */
	private void transferPreferredWithLessNumber(Coin amount, List<TransactionOutput> lessThanList, List<TransactionOutput> moreThanList, List<TransactionOutput> outputs) {
		if(moreThanList.size() > 0) {
			//有比本次交易大的未输出交易，直接使用其中最小的一个
			selectOneOutput(moreThanList, outputs);
		} else {
			//没有比本次交易最大的未输出交易
			selectSmallChange(amount, lessThanList, outputs);
		}
	}

	/*
 * 交易选择 -- 以交易数据小优先，该种机制尽量选择一笔输入
 */
	private void transferPreferredWithLessNumberMulUser(Coin amount, HashMap<String,List<TransactionOutput>> lessThanList,  HashMap<String,List<TransactionOutput>> moreThanList,  HashMap<String,List<TransactionOutput>> outputs) {
		if(moreThanList.size() > 0) {
			//有比本次交易大的未输出交易，直接使用其中最小的一个
			selectOneOutputMulUser(moreThanList, outputs);
		} else {
			//没有比本次交易最大的未输出交易
			selectSmallChangeMulUser(amount, lessThanList, outputs);
		}
	}

	/*
	 * 选择列表里面金额最小的一笔作为输出
	 */
	private void selectOneOutput(List<TransactionOutput> moreThanList, List<TransactionOutput> outputs) {
		if(moreThanList == null || moreThanList.size() == 0) {
			return;
		}
		Collections.sort(moreThanList, new Comparator<TransactionOutput>() {
			@Override
			public int compare(TransactionOutput o1, TransactionOutput o2) {
				long v1 = o1.getValue();
				long v2 = o2.getValue();
				if(v1 == v2) {
					return 0;
				} else if(v1 > v2) {
					return 1;
				} else {
					return -1;
				}
			}
		});
		outputs.add(moreThanList.get(0));
	}

	/*
 * 出现的第一笔为输出
 */
	private void selectOneOutputMulUser(HashMap<String,List<TransactionOutput>> moreThanList, HashMap<String,List<TransactionOutput>> outputs) {
		if(moreThanList == null || moreThanList.size() == 0) {
			return;
		}
		Iterator<String> moreit = moreThanList.keySet().iterator();
		while (moreit.hasNext()) {
			String address = moreit.next();
			List<TransactionOutput> userMoreThanList = moreThanList.get(address);
			if(userMoreThanList.size()==0) {
				continue;
			}else {
				TransactionOutput out = userMoreThanList.get(0);
				List<TransactionOutput> oneList = new ArrayList<TransactionOutput>();
				oneList.add(out);
				outputs.put(address,oneList);
				return;
			}
		}
	}

	/*
	 * 选择零钱，原则是尽量少的找钱，尽量少的使用输出笔数
	 */
	private void selectSmallChange(Coin amount, List<TransactionOutput> lessThanList, List<TransactionOutput> outputs) {
		if(lessThanList == null || lessThanList.size() == 0) {
			return;
		}
		//排序
		Collections.sort(lessThanList, new Comparator<TransactionOutput>() {
			@Override
			public int compare(TransactionOutput o1, TransactionOutput o2) {
				long v1 = o1.getValue();
				long v2 = o2.getValue();
				if(v1 == v2) {
					return 0;
				} else if(v1 > v2) {
					return 1;
				} else {
					return -1;
				}
			}
		});

		//已选择的金额
		Coin total = Coin.ZERO;
		//从小到大选择
		for (TransactionOutput transactionOutput : lessThanList) {
			outputs.add(transactionOutput);
			total = total.add(Coin.valueOf(transactionOutput.getValue()));
			if(total.isGreaterThan(amount)) {
				//判断是否可以移除最小的几笔交易
				List<TransactionOutput> removeList = new ArrayList<TransactionOutput>();
				for (TransactionOutput to : outputs) {
					total = total.subtract(Coin.valueOf(to.getValue()));
					if(total.isGreaterThan(amount)) {
						removeList.add(to);
					} else {
						break;
					}
				}
				if(removeList.size() > 0) {
					outputs.removeAll(removeList);
				}
				break;
			}
		}
	}

	/*
	 * 选择零钱，原则先后顺序
	 */
	private void selectSmallChangeMulUser(Coin amount, HashMap<String,List<TransactionOutput>> lessThanList, HashMap<String,List<TransactionOutput>> outputs) {
		if(lessThanList == null || lessThanList.size() == 0) {
			return;
		}
		//已选择的金额
		Coin total = Coin.ZERO;

		Iterator<String> lessit = lessThanList.keySet().iterator();
		while (lessit.hasNext()) {
			String address = lessit.next();
			List<TransactionOutput> userLessThanList=lessThanList.get(address);
			List<TransactionOutput> userOutputList= new ArrayList<TransactionOutput>();
			//从小到大选择
			for (TransactionOutput transactionOutput : userLessThanList) {
				userOutputList.add(transactionOutput);
				total = total.add(Coin.valueOf(transactionOutput.getValue()));
				if (total.isGreaterThan(amount)) {
					break;
				}
			}
			outputs.put(address,userOutputList);
		}
	}

	/**
	 * 初始化一个普通帐户
	 * @return Address
	 * @throws IOException
	 * @throws Exception
	 */
	public Address createNewAccount() throws IOException {
		locker.lock();
		try {

//			ECKey key = ECKey.fromPrivate(new BigInteger(""));
			ECKey key = new ECKey();

			Address address = Address.fromP2PKHash(network, network.getSystemAccountVersion(), Utils.sha256hash160(key.getPubKey(false)));

			address.setBalance(Coin.ZERO);
			address.setUnconfirmedBalance(Coin.ZERO);

			Account account = new Account(network);

			account.setPriSeed(key.getPrivKeyBytes());
			account.setAccountType(address.getVersion());
			account.setAddress(address);
			account.setMgPubkeys(new byte[][] {key.getPubKey(true)});
			account.signAccount(key, null);

			File accountFile = new File(accountDir, address.getBase58()+".dat");

			FileOutputStream fos = new FileOutputStream(accountFile);
			try {
				//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
				fos.write(account.serialize());
			} finally {
				fos.close();
			}

			account.setEcKey(key);
			accountList.add(account);

			return address;
		} finally {
			locker.unlock();
		}
	}

	/**
	 * 初始化一个普通帐户
	 * @return Address
	 * @throws IOException
	 * @throws Exception
	 */
	public JSONObject createNewAccount(int count) throws IOException {
		File accountFile = null;
		FileOutputStream fos = null;
		locker.lock();
		JSONObject addresses = new JSONObject();
		JSONArray addressesArrays = new JSONArray();
		accountFile = new File(accountDir, "wallet.dat");
		fos = new FileOutputStream(accountFile,true);
		List<Account> newAccountList = new ArrayList<Account>();

		try {
			for (int i=0;i<count;i++) {
//			ECKey key = ECKey.fromPrivate(new BigInteger(""));
				ECKey key = new ECKey();

				Address address = Address.fromP2PKHash(network, network.getSystemAccountVersion(), Utils.sha256hash160(key.getPubKey(false)));

				address.setBalance(Coin.ZERO);
				address.setUnconfirmedBalance(Coin.ZERO);

				Account account = new Account(network);

				account.setPriSeed(key.getPrivKeyBytes());
				account.setAccountType(address.getVersion());
				account.setAddress(address);
				account.setMgPubkeys(new byte[][]{key.getPubKey(true)});
				account.signAccount(key, null);
				account.setEcKey(key);
				accountList.add(account);
				addressesArrays.put(i,account.getAddress().getBase58());
				newAccountList.add(account);
				try {
					//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
					fos.write(account.serialize());
					fos.flush();
				} finally {

				}
			}
			addresses.put("addresses",addressesArrays);
			//init();
			transactionStoreProvider.addAddress(newAccountList);
			for(Account account:newAccountList) {
				blockStoreProvider.addAccountFilter(account.getAddress().getHash160());
			}
			return addresses;
		}catch (Exception e){
			log.info("创建多用户地址出错："+e);
		} finally {
			locker.unlock();
			fos.close();
		}
		return null;
	}

	/**
	 * 初始化一个认证帐户
	 * @param mgPw			帐户管理密码
	 * @param trPw  		帐户交易密码
	 * @param accountBody   帐户信息
	 * @param certpw        管理密码
	 * @return Address
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws VerificationException
	 */
	public Account createNewCertAccount(String mgPw, String trPw, AccountBody accountBody,  String certpw, String managerAddress) throws FileNotFoundException, IOException, VerificationException  {

		//密码位数和难度检测
		if(!validPassword(mgPw) || !validPassword(trPw)) {
			throw new VerificationException("密码需6位或以上，且包含字母和数字");
		}

		//强制交易密码和帐户管理密码不一样
		Utils.checkState(!mgPw.equals(trPw), "账户管理密码和交易密码不能一样");

        System.out.println(network.getSystemAccountVersion() + "====");

		System.out.println(Address.fromBase58(network,managerAddress).getVersion() + "------" + network.getSystemAccountVersion());
		if(Address.fromBase58(network,managerAddress).getVersion()==network.getSystemAccountVersion()) {
			throw new VerificationException("系统账户不具备该权限");
		}

		locker.lock();
		try {
			Account account = genAccountInfos(mgPw, trPw, accountBody,certpw,managerAddress);

			accountList.add(account);

			byte[] hash160 = account.getAddress().getHash160();
			blockStoreProvider.addAccountFilter(hash160);
			transactionStoreProvider.addAddress(hash160);

			return account;
		} catch (Exception e) {
			log.error("初始化认证账户出错：{}", e.getMessage(), e);
			throw new VerificationException(e);
		} finally {
			locker.unlock();
		}
	}

	/**
	 * 修改认证账户的信息
	 * @param mgPw
	 * @param address
	 * @param accountBody
	 * @return BroadcastResult
	 * @throws VerificationException
	 */
	public BroadcastResult updateCertAccountInfo(String mgPw, String address, AccountBody accountBody) throws VerificationException  {

		//密码位数和难度检测
		if(!validPassword(mgPw)) {
			return new BroadcastResult(false, "密码错误");
		}

		Account account = null;
		if(StringUtil.isEmpty(address)) {
			account = getCertAccount();
		} else {
			account = getAccount(address);
		}

		if(account == null) {
			return new BroadcastResult(false, "账户不存在");
		}

		ECKey[] eckey = account.decryptionMg(mgPw);
		if(eckey == null) {
			return new BroadcastResult(false, "密码错误");
		}

		locker.lock();
		try {
			CertAccountUpdateTransaction cutx = new CertAccountUpdateTransaction(network, account.getAddress().getHash160(), account.getMgPubkeys(), account.getTrPubkeys(), accountBody,account.getSupervisor(),account.getLevel());
			cutx.sign(account, Definition.TX_VERIFY_MG);

			cutx.verify();
			cutx.verifyScript();

			//验证交易合法才广播
			//这里面同时会判断是否被验证过了
			TransactionValidatorResult rs = transactionValidator.valDo(cutx).getResult();
			if(!rs.isSuccess()) {
				return new BroadcastResult(false, rs.getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			MempoolContainer.getInstace().add(cutx);
			try {
				BroadcastResult result = peerKit.broadcast(cutx).get();
				//等待广播回应
				if(result.isSuccess()) {
					result.setHash(cutx.getHash());

					account.setBody(accountBody);
					account.setAccountTransaction(cutx);

					//签名帐户
					account.signAccount(account.getMgEckeys()[0], account.getMgEckeys()[1]);
					File accountFile = new File(accountDir + File.separator,  account.getAddress().getBase58() +".dat");
					FileOutputStream fos = new FileOutputStream(accountFile);
					try {
						//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
						fos.write(account.serialize());
					} finally {
						fos.close();
					}

					//更新交易记录
					transactionStoreProvider.processNewTransaction(new TransactionStore(network, cutx));
				}
				return result;
			} catch (Exception e) {
				return new BroadcastResult(false, e.getMessage());
			}
		} finally {
			account.resetKey();
			locker.unlock();
		}
	}

	/**
	 * 吊销认证账户的信息
	 * @param revokeAddress
	 * @param mgPw
	 * @param address
	 * @return BroadcastResult
	 * @throws VerificationException
	 */
	public BroadcastResult revokeCertAccount(String revokeAddress, String mgPw, String address) throws VerificationException  {

        //密码位数和难度检测
        if(!validPassword(mgPw)) {
            return new BroadcastResult(false, "密码错误");
        }

        Account account = null;
        if(StringUtil.isEmpty(address)) {
            account = getCertAccount();
        } else {
            account = getAccount(address);
        }

        if(account == null) {
            return new BroadcastResult(false, "账户不存在");
        }

        ECKey[] eckey = account.decryptionTr(mgPw);
        if(eckey == null) {
            return new BroadcastResult(false, "密码错误");
        }

        Address raddress = new Address(network,revokeAddress);
        locker.lock();
        try {
            CertAccountRevokeTransaction cutx = new CertAccountRevokeTransaction(network,raddress.getHash160(), account.getMgPubkeys(), account.getTrPubkeys(),account.getAddress().getHash160(),account.getLevel());
            cutx.sign(account, Definition.TX_VERIFY_TR);
            cutx.verify();
            cutx.verifyScript();

			//验证交易合法才广播
			//这里面同时会判断是否被验证过了

			TransactionValidatorResult rs = transactionValidator.valDo(cutx).getResult();
			if(!rs.isSuccess()) {
				return new BroadcastResult(false, rs.getMessage());
			}

            //加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
            MempoolContainer.getInstace().add(cutx);
            try {
                BroadcastResult result = peerKit.broadcast(cutx).get();
                //等待广播回应
                if(result.isSuccess()) {
                    result.setHash(cutx.getHash());
                    //account.setAccountTransaction(cutx);

                    //更新交易记录
                    transactionStoreProvider.processNewTransaction(new TransactionStore(network, cutx));
                }
                return result;
            } catch (Exception e) {
                return new BroadcastResult(false, e.getMessage());
            }
        } finally {
            account.resetKey();
            locker.unlock();
        }
    }

    public boolean isCertAccountRevoked(byte[] hash160){
        return chainstateStoreProvider.isCertAccountRevoked(hash160);
    }

    /**
	 * 认证账户修改密码
	 * @param oldMgpw
	 * @param newMgpw
	 * @param newTrpw
	 * @param address
	 * @return BroadcastResult
	 */
	public BroadcastResult certAccountEditPassword(String oldMgpw, String newMgpw, String newTrpw, String address) {
		//密码位数和难度检测
		if(!validPassword(oldMgpw)) {
			return new BroadcastResult(false, "密码错误");
		}
		if(!validPassword(newMgpw)) {
			return new BroadcastResult(false, "新账户管理密码不合法");
		}
		if(!validPassword(newTrpw)) {
			return new BroadcastResult(false, "新交易密码不合法");
		}

		Account account = null;
		if(StringUtil.isEmpty(address)) {
			account = getCertAccount();
		} else {
			account = getAccount(address);
		}

		if(account == null) {
			return new BroadcastResult(false, "账户不存在");
		}

		ECKey[] eckey = account.decryptionMg(oldMgpw);

		if(eckey == null) {
			return new BroadcastResult(false, "旧密码错误");
		}
		account.setMgEckeys(eckey);
		locker.lock();
		try {
			Account tempAccount = account.clone();

			ECKey seedPri = ECKey.fromPublicOnly(tempAccount.getPriSeed());
			byte[] seedPribs = seedPri.getPubKey(false);

			//生成账户管理的私匙
			BigInteger mgPri1 = AccountTool.genPrivKey1(seedPribs, newMgpw.getBytes());
			//生成交易的私匙
			BigInteger trPri1 = AccountTool.genPrivKey1(seedPribs, newTrpw.getBytes());

			BigInteger mgPri2 = AccountTool.genPrivKey2(seedPribs, newMgpw.getBytes());
			BigInteger trPri2 = AccountTool.genPrivKey2(seedPribs, newTrpw.getBytes());

			ECKey mgkey1 = ECKey.fromPrivate(mgPri1);
			ECKey mgkey2 = ECKey.fromPrivate(mgPri2);

			ECKey trkey1 = ECKey.fromPrivate(trPri1);
			ECKey trkey2 = null;

			tempAccount.setMgPubkeys(new byte[][] {mgkey1.getPubKey(true), mgkey2.getPubKey(true)});	//存储帐户管理公匙
			tempAccount.setTrPubkeys(new byte[][] {trkey1.getPubKey(true)});//存储交易公匙

			CertAccountUpdateTransaction cutx = new CertAccountUpdateTransaction(network, tempAccount.getAddress().getHash160(), tempAccount.getMgPubkeys(), tempAccount.getTrPubkeys(), tempAccount.getBody(),account.getSupervisor(),account.getLevel());
			cutx.sign(account, Definition.TX_VERIFY_MG);

			cutx.verify();
			cutx.verifyScript();

			//验证交易合法才广播
			//这里面同时会判断是否被验证过了
			TransactionValidatorResult rs = transactionValidator.valDo(cutx).getResult();
			if(!rs.isSuccess()) {
				return new BroadcastResult(false, rs.getMessage());
			}

			//加入内存池，因为广播的Inv消息出去，其它对等体会回应getDatas获取交易详情，会从本机内存取出来发送
			MempoolContainer.getInstace().add(cutx);
			try {
				BroadcastResult result = peerKit.broadcast(cutx).get();
				//等待广播回应
				if(result.isSuccess()) {
					result.setHash(cutx.getHash());

					account.setMgPubkeys(tempAccount.getMgPubkeys());
					account.setTrPubkeys(tempAccount.getTrPubkeys());
					account.setAccountTransaction(cutx);

					//签名帐户
					tempAccount.signAccount(mgkey1, mgkey2);
					File accountFile = new File(accountDir + File.separator,  tempAccount.getAddress().getBase58() +".dat");
					FileOutputStream fos = new FileOutputStream(accountFile);
					try {
						//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
						fos.write(tempAccount.serialize());
					} finally {
						tempAccount.resetKey();
						fos.close();
					}
					//更新交易记录
					transactionStoreProvider.processNewTransaction(new TransactionStore(network, cutx));
				}
				return result;
			} catch (Exception e) {
				return new BroadcastResult(false, e.getMessage());
			}
		} catch (CloneNotSupportedException e1) {
			log.error("error", e1);
			return new BroadcastResult(false, e1.getMessage());
		} finally {
			account.resetKey();
			locker.unlock();
		}
	}

	/*
	 * 生成帐户信息
	 */
	private Account genAccountInfos(String mgPw, String trPw, AccountBody accountBody,String certpw,String managerAddress) throws FileNotFoundException, IOException, VerificationException {

		if(accountBody == null) {
			throw new VerificationException("缺少账户主体");
		}
		//验证权限
		Account managerAccount = getManagerAccount(managerAddress);
		if(managerAccount == null) {
			throw new VerificationException("没有权限生成认证账户");
		}

		//是否加密
		ECKey[] trEckeys = null;
		if(managerAccount.isEncryptedOfTr()) {
			if(StringUtil.isEmpty(certpw)) {
				throw new VerificationException("管理账户已加密，缺少密码");
			} else {
				try {
					trEckeys = managerAccount.decryptionTr(certpw);
					if(trEckeys == null) {
						throw new VerificationException("解密失败，密码错误");
					}
				} catch (Exception e) {
					throw new VerificationException("解密失败，密码错误");
				} finally {
					managerAccount.resetKey();
				}
			}
		} else {
			trEckeys = managerAccount.getTrEckeys();
		}

		//生成新的帐户信息
		//生成私匙公匙对
		ECKey key = new ECKey();
		//取生成的未压缩的公匙做为该帐户的永久私匙种子
		byte[] prikeySeed = key.getPubKey(false);

		//生成账户管理的私匙
		BigInteger mgPri1 = AccountTool.genPrivKey1(prikeySeed, mgPw.getBytes());
		//生成交易的私匙
		BigInteger trPri1 = AccountTool.genPrivKey1(prikeySeed, trPw.getBytes());

		BigInteger mgPri2 = AccountTool.genPrivKey2(prikeySeed, mgPw.getBytes());

		//默认生成一个系统帐户

		//随机生成一个跟前面没关系的私匙公匙对，用于产出地址
		ECKey addressKey = new ECKey();
		//以base58的帐户地址来命名帐户文件
		Address address = AccountTool.newAddress(network, network.getCertAccountVersion(), addressKey);

		ECKey mgkey1 = ECKey.fromPrivate(mgPri1);
		ECKey mgkey2 = ECKey.fromPrivate(mgPri2);

		ECKey trkey1 = ECKey.fromPrivate(trPri1);


		//帐户信息
		Account account = new Account(network);
		account.setStatus((byte) 0);
		account.setSupervisor(managerAccount.getAddress().getHash160() );
		account.setlevel(managerAccount.getLevel()+1);
		account.setAccountType(network.getSystemAccountVersion());
		account.setAddress(address);
		account.setPriSeed(key.getPubKey(true)); //存储压缩后的种子私匙
		account.setMgPubkeys(new byte[][] {mgkey1.getPubKey(true), mgkey2.getPubKey(true)});	//存储帐户管理公匙
		account.setTrPubkeys(new byte[][] {trkey1.getPubKey(true)});//存储交易公匙

		account.setBody(accountBody);

		//签名帐户
		account.signAccount(mgkey1,mgkey2);

		File accountFile = new File(accountDir + File.separator,  address.getBase58()+".dat");
		if(!accountFile.getParentFile().exists()) {
			accountFile.getParentFile().mkdir();
		}

		FileOutputStream fos = new FileOutputStream(accountFile);
		try {
			//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
			fos.write(account.serialize());
		} finally {
			fos.close();
		}
		//广播帐户注册消息
		CertAccountRegisterTransaction tx = new CertAccountRegisterTransaction(network, account.getAddress().getHash160(), account.getMgPubkeys(), account.getTrPubkeys(), accountBody,account.getSupervisor(),managerAccount.getLevel());

		tx.calculateSignature(managerAccount.getAccountTransaction().getHash(), trEckeys[0], null,managerAccount.getAddress().getHash160(),Definition.TX_VERIFY_TR);

		tx.verify();
		tx.verifyScript();

		peerKit.broadcastMessage(tx);
		account.setAccountTransaction(tx);
		return account;
	}

    /*
     * 获取网络认证管理账户，如果没有则返回Null
     */
    private Account getManagerAccount(String managerAddress) {
        if(managerAddress ==  null){
            Account account =   getCertAccount();
            if(account.getLevel() >= Configure.MAX_CERT_LEVEL )
                return null;
            return account;
        }
        for (Account tmpaccount : accountList) {
            if(managerAddress.equals(tmpaccount.getAddress().getBase58())) {
                if( tmpaccount.getLevel() >= Configure.MAX_CERT_LEVEL )
                    return null;
                return tmpaccount;
            }
        }
        return null;
    }

	/**
	 * 备份钱包
	 * @param backupFilePath 备份文件路径
	 * @return Result 成功则result.message返回备份文件的完整路径
	 * @throws IOException
	 */
	public Result backupWallet(String backupFilePath) throws IOException {
		//目录是否存在，不存在则创建，如果传入的是一个目录，则自动生成备份的文件名
		if(StringUtils.isEmpty(backupFilePath)) {
			return new Result(false, "备份路径为空");
		}
		//账户存在才能备份
		if(accountList == null || accountList.size() == 0) {
			log.warn("系统内没有可备份的账户");
			return new Result(false, "系统内没有可备份的账户");
		}
		File backupFile = new File(backupFilePath);
		//判断上级目录是否存在，不存在则创建
		if(!backupFile.getParentFile().exists() && !backupFile.getParentFile().mkdirs()) {
			return new Result(false, "创建目录失败");
		}
		//如果传入的文件夹，则生成备份文件
		if(backupFile.isDirectory()) {
			if(!backupFile.exists() && !backupFile.mkdir()) {
				return new Result(false, "创建目录失败");
			}
			backupFile = new File(backupFile, "wallet_backup_".concat(DateUtil.convertDate(new Date(TimeService.currentTimeMillis()), "yyyyMMddHHmm")).concat(".dat"));
		}
		//创建备份文件
		if(!backupFile.exists() && !backupFile.createNewFile()) {
			return new Result(false, "创建文件失败");
		}
		//备份账户
		FileOutputStream fos = new FileOutputStream(backupFile);
		try {
			for (Account account : accountList) {
				fos.write(account.serialize());
			}
			return new Result(true, backupFile.getAbsolutePath());
		} finally {
			fos.close();
		}
	}

	/**
	 * 导入钱包
	 * @param walletFilePath 钱包文件路径
	 * @return boolean 是否导入成功
	 * @throws IOException
	 */
	public Result importWallet(String walletFilePath) throws IOException {
		//导入的文件路径不能为空
		if(StringUtils.isEmpty(walletFilePath)) {
			return new Result(false, "导入的文件路径为空");
		}
		File walletFile = new File(walletFilePath);
		//判断将要导入的钱包文件是否存在
		if(!walletFile.exists()) {
			return new Result(false, "要导入的钱包文件不存在");
		}
		//覆盖账户
		FileInputStream fis = new FileInputStream(walletFile);
		try {
			byte[] datas = new byte[fis.available()];
			fis.read(datas);

			int index = 0;
			//导入的账户列表
			List<Account> importAccountList = new ArrayList<Account>();
			while(index < datas.length) {
				Account ac = Account.parse(datas, index, network);
				index += ac.serialize().length;
				try {
					//验证不通过的忽略
					ac.verify();
					importAccountList.add(ac);
				} catch (Exception e) {
					log.warn("导入{}时出错", ac.getAddress().getBase58(), e);
				}
			}

			if(importAccountList.size() == 0) {
				return new Result(false, "导入了0个账户");
			}
			//备份原账户

			String newBackupFile =  "wallet_auto_backup_".concat(DateUtil.convertDate(new Date(TimeService.currentTimeMillis()), "yyyyMMddHHmmss")).concat(".dat.temp");
			new File(accountDir+ File.separator,   "wallet.dat")
					.renameTo(new File(accountDir, newBackupFile));

			for (Account account : accountList) {
				String base58 = account.getAddress().getBase58();
				newBackupFile = base58 + "_auto_backup_".concat(DateUtil.convertDate(new Date(TimeService.currentTimeMillis()), "yyyyMMddHHmmss")).concat(".dat.temp");
				File temp = new File(accountDir+ File.separator, base58 + ".dat");
				if(temp.exists()) {
					temp.renameTo(new File(accountDir+ File.separator, newBackupFile));
				}
			}

			File accountFile = new File(accountDir+ File.separator, "wallet.dat");
			FileOutputStream fos = new FileOutputStream(accountFile);
			try {
				for (Account account : importAccountList) {
					fos.write(account.serialize());
				}
			} finally {
				fos.close();
			}
			//重新加载账户
			init();
			/*
			loadAccount();
			//更新余额
			loadBalanceFromChainstateAndUnconfirmedTransaction(getAccountHash160s());
			*/
			return new Result(true, "成功导入了"+importAccountList.size()+"个账户");
		} catch (Exception e) {
			log.error("导入钱包失败，{}", e.getMessage(), e);
			return new Result(false, "导入钱包失败,"+e.getMessage());
		} finally {
			fis.close();
		}
	}

	/**
	 * 加密钱包
	 * @param password  密码
	 * @return Result
	 */
	public Result encryptWallet(String password,String address) {
		//密码位数和难度检测
		if(!validPassword(password)) {
			return new Result(false, "输入的密码需6位或以上，且包含字母和数字");
		}

		int successCount = 0; //成功个数
		Account account = null;
		if(address!=null){
			account = getAccount(address);
			if(account == null){
				return new Result(false,"账户"+address+"不存在");
			}
		}else {
			account = getDefaultAccount();
		}

		if(account.isEncrypted()) {
			return new Result(false,"账户"+address+"已经加密");
		}
		ECKey eckey = account.getEcKey();
		try {
			ECKey newKey = eckey.encrypt(password);
			account.setEcKey(newKey);
			account.setPriSeed(newKey.getEncryptedPrivateKey().getEncryptedBytes());

			//重新签名
			account.signAccount(eckey, null);

			//回写到钱包文件
			File accountFile = new File(accountDir, account.getAddress().getBase58()+".dat");

			FileOutputStream fos = new FileOutputStream(accountFile);
			try {
				//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
				fos.write(account.serialize());
				successCount++;
			} finally {
				fos.close();
			}
		} catch (Exception e) {
			log.error("加密 {} 失败: {}", account.getAddress().getBase58(), e.getMessage(), e);
			return new Result(false, String.format("加密 %s 失败: %s", account.getAddress().getBase58(), e.getMessage()));
		} finally {
			eckey = null;
		}

		String message = null;

		message = "成功加密"+account.getAddress();

		return new Result(true, message);
	}

	public Result encryptWallet(String password) {
		//密码位数和难度检测
		if(!validPassword(password)) {
			return new Result(false, "输入的密码需6位或以上，且包含字母和数字");
		}

		int successCount = 0; //成功个数
		//加密钱包
		File accountFile = new File(accountDir, "wallet.dat");
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(accountFile);
		}catch (Exception e){
			return new Result(false, "创建文件失败");
		}

		//判断是否已经加密了
		boolean isEncrypted=false;
		for (Account account : accountList){
			if(account.isCertAccount())
				continue;
			if(!account.isEncrypted()) {
				continue;
			}else{
				try{
					account.resetKey(password);
					ECKey eckey = account.getEcKey();
					account.setEcKey(eckey.decrypt(password));
				}catch (Exception e){
					return new Result(false, "钱包存在已经加密的账户且密码与当前输入的密码不想等，不能加密");
				}
			}
		}

		if(isEncrypted){
			return new Result(false, "钱包存在已经加密的账户，不能加密");
		}

		for (Account account : accountList) {
			if(account.isCertAccount())
				continue;
			ECKey eckey = account.getEcKey();
			try {
				ECKey newKey = eckey.encrypt(password);
				account.setEcKey(newKey);
				account.setPriSeed(newKey.getEncryptedPrivateKey().getEncryptedBytes());

				//重新签名
				account.signAccount(eckey, null);
				//回写到钱包文件
				try {
					//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
					fos.write(account.serialize());
					successCount++;
				} finally {

				}
			} catch (Exception e) {
				log.error("加密 {} 失败: {}", account.getAddress().getBase58(), e.getMessage(), e);
				return new Result(false, String.format("加密 %s 失败: %s", account.getAddress().getBase58(), e.getMessage()));
			} finally {
				eckey = null;
			}
		}
		String message = null;
		try {
			fos.close();
		}catch (Exception e){
			//TODO
		}
		if(successCount > 0) {
			message = "成功加密"+successCount+"个账户";
		} else {
			message = "账户已加密，无需重复加密";
		}
		return new Result(true, message);
	}

	public Result decryptWallet(String password) {
		for(Account account:accountList) {
			Result rs = decryptAccount(password, account.getAddress().getBase58(), Definition.TX_VERIFY_MG);
			if(!rs.isSuccess()){
				lockWallet();
				return rs;
			}
		}
		return new Result(true,"解密钱包成功");
	}

	public Result lockWallet(){
		isLockWalletNow  = true;
		isUnlockedByCmd = false;
		return new Result(true,"锁定成功");
//		resetKeys();
	}


	public Result importPriKey(String prikey){
		Result ret = null;
		FileOutputStream fos = null;
		String importFile = "";
		Address addressTemp = null;
		try{
			BigInteger pri = new BigInteger( Hex.decode(prikey));

			ECKey keyTemp = ECKey.fromPrivate(pri);
			addressTemp = AccountTool.newAddress(network, keyTemp);

			Account account = new Account(network);
			account.setAddress(addressTemp);

			account.setEcKey(keyTemp);
			account.setMgPubkeys(new byte[][]{ keyTemp.getPubKey()});
			account.setPriSeed(keyTemp.getPrivKeyBytes());
			account.signAccount();
			account.verify();

			File accountFile = new File(accountDir+ File.separator, addressTemp.getBase58()+".dat");
			importFile = accountDir+File.separator+addressTemp.getBase58()+".dat";
			fos = new FileOutputStream(accountFile);
			fos.write(account.serialize());
		} catch (Exception e){
			ret = new Result(false,"密钥错误");
			return ret;
		} finally {
			try {
				fos.close();
			}catch (Exception e){
				//donothing
			}
		}
		try {
			importWallet(importFile);
		}catch (Exception e){
			ret = new Result(false,"导入失败");
			return ret;
		}
		ret = new Result(true,"导入账户"+addressTemp.getBase58()+"成功");
		return  ret;
	}

	public Result unlockWallet(String password,int unlockSec) {
		if(!isWalletEncrypted()) {
			return new Result(true,"钱包未加密");
		}else{
			Result rs = decryptWallet(password);
			if(!rs.isSuccess()){
				return rs;
			}
		}
		unlocktime = TimeService.currentTimeSeconds() + unlockSec;
		isLockWalletNow = false;
		isUnlockedByCmd = true;
		new Thread("lockWalletThread") {
			@Override
			public void run() {
				while (!isLockWalletNow) {
					if (TimeService.currentTimeSeconds() - unlocktime > 0) {
						break;
					}
					try {
						Thread.sleep(100L);
					}catch (Exception e){
					}
				}
				unlocktime = TimeService.currentTimeSeconds();
				isUnlockedByCmd = false;
				resetKeys();
			}
		}.start();
		return new Result(true,"解锁成功");
	}

	/**
	 * 解密钱包
	 * @param password  密码
	 * @return Result
	 */
	public Result decryptAccount(String password, String address) {
		return decryptAccount(password,address,Definition.TX_VERIFY_MG);
	}

	/**
	 * 解密钱包
	 * @param password  密码
	 * @param type  1账户管理私钥 ，2交易私钥
	 * @return Result
	 */
	public Result decryptAccount(String password, String address, int type) {
		//密码位数和难度检测
		if(!validPassword(password)) {
			return new Result(false, "密码错误");
		}
		Account account = null;
		if(address == null) {
			account = getDefaultAccount();
		}else{
			account = getAccount(address);
		}
		if(account == null){
			return new Result(false, "账户"+address+"不存在");
		}

		if(account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) {
			//普通账户的解密
			account.resetKey(password);
			ECKey eckey = account.getEcKey();
			try {
				account.setEcKey(eckey.decrypt(password));
			} catch (Exception e) {
				log.error("解密失败, "+e.getMessage(), e);
				account.setEcKey(eckey);
				return new Result(false, "密码错误");
			}
		} else if(account.getAccountType() == network.getCertAccountVersion()) {
			//认证账户的解密
			ECKey[] keys = null;
			if(type == Definition.TX_VERIFY_MG) {
				keys = account.decryptionMg(password);
			} else {
				keys = account.decryptionTr(password);
			}
			if(keys == null) {
				return new Result(false, "密码错误");
			}
		}
		return new Result(true, "解密成功");
	}

	/**
	 * 修改钱包密码
	 * 如果没有加密的账户，会被新密码加密
	 * @param oldPassword   原密码
	 * @param newPassword 	新密码
	 * @return Result
	 */
	public Result changeWalletPassword(String oldPassword, String newPassword) {
		return changeWalletPassword(oldPassword, newPassword,1);
	}

	/**
	 * 修改钱包密码
	 * 如果没有加密的账户，会被新密码加密
	 * @param oldPassword   原密码
	 * @param newPassword 	新密码
	 * @return Result
	 */
	public Result changeWalletPassword(String oldPassword, String newPassword,String address) {
		return changeWalletPassword(oldPassword, newPassword,address ,1);
	}

	/**
	 * 修改认证账户的密码
	 * @param oldPassword	旧密码
	 * @param newPassword	新密码
	 * @param type  1账户管理私钥 ，2交易私钥
	 * @return Result
	 */
	public Result changeWalletPassword(String oldPassword, String newPassword,String address ,int type) {
		//密码位数和难度检测
		if(!validPassword(oldPassword) || !validPassword(newPassword)) {
			return new Result(false, "密码需6位或以上，且包含字母和数字");
		}

		//先解密
		//如果修改认证账户，如果修改的是账户管理密码，这里的原密码就是账户管理密码 ，
		//如果修改的是交易密码，这里的原密码也是账户管理密码，因为必须要账户管理密码才能修改
		Result res = decryptAccount(oldPassword,address);
		if(!res.isSuccess()) {
			return res;
		}

		File normalAccountFile = new File(accountDir, "wallet.dat");
		FileOutputStream normalfos = null;
		try {
			normalfos = new FileOutputStream(normalAccountFile,true);
		}catch (Exception e){
			return new Result(false, "打开文件wallet.dat失败");
		}
		int successCount = 0; //成功个数
		//加密钱包
		Account account = getAccount(address);
		try {
			if(account.isCertAccount()) {

				//认证账户
				//生成私匙
				ECKey seedPri = ECKey.fromPublicOnly(account.getPriSeed());
				byte[] seedPribs = seedPri.getPubKey(false);

				BigInteger pri1 = AccountTool.genPrivKey1(seedPribs, newPassword.getBytes());
				BigInteger pri2 = AccountTool.genPrivKey2(seedPribs, newPassword.getBytes());

				ECKey key1 = ECKey.fromPrivate(pri1);
				ECKey key2 = ECKey.fromPrivate(pri2);

				//重新设置账户的公钥
				ECKey[] oldMgEckeys = account.getMgEckeys();
				if(type == 1) {
					account.setMgEckeys(new ECKey[] {key1, key2});
					account.setMgPubkeys(new byte[][] {key1.getPubKey(true), key2.getPubKey(true)});
				} else {
					account.setTrEckeys(new ECKey[]{key1});
					account.setTrPubkeys(new byte[][] {key1.getPubKey(true)});
				}
				//重新签名
				account.signAccount();
				account.verify();

				//广播
				CertAccountUpdateTransaction rtx = new CertAccountUpdateTransaction(network, account.getAddress().getHash160(),
						account.getMgPubkeys(), account.getTrPubkeys(), account.getBody(),account.getSupervisor(),account.getLevel());

				rtx.calculateSignature(account.getAccountTransaction().getHash(), oldMgEckeys[0], oldMgEckeys[1], account.getAddress().getHash160(), Definition.TX_VERIFY_MG);
				rtx.verify();
				rtx.verifyScript();

				MempoolContainer.getInstace().add(rtx);

				BroadcastResult broadcastResult = peerKit.broadcast(rtx).get();
				if(broadcastResult.isSuccess()) {
					account.setAccountTransaction(rtx);
					//回写到钱包文件
					File accountFile = new File(accountDir, account.getAddress().getBase58()+".dat");
					FileOutputStream fos = new FileOutputStream(accountFile);
					try {
						//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
						fos.write(account.serialize());
						successCount++;
					} finally {
						fos.close();
					}
				} else {
					log.error(broadcastResult.getMessage());
				}
			} else {
				//普通账户，也就无所谓管理或者交易密码了
				ECKey eckey = account.getEcKey();
				ECKey newKey = eckey.encrypt(newPassword);
				account.setEcKey(newKey);
				account.setPriSeed(newKey.getEncryptedPrivateKey().getEncryptedBytes());

				//重新签名
				account.signAccount(eckey, null);

				account.verify();

				//回写到钱包文件

				try {
					//数据存放格式，type+20字节的hash160+私匙长度+私匙+公匙长度+公匙，钱包加密后，私匙是
					normalfos.write(account.serialize());
					successCount++;
				} finally {

				}
				eckey = null;
			}
		} catch (Exception e) {
			log.error("加密 {} 失败: {}", account.getAddress().getBase58(), e.getMessage(), e);
			return new Result(false, String.format("加密 %s 失败: %s", account.getAddress().getBase58(), e.getMessage()));
		} finally {
			account.resetKey();
			try {
				normalfos.close();
			}catch (Exception e){
				//TODO
			}
		}
		String message = "修改密码成功";
		return new Result(true, message);
	}


	/**
	 * 修改认证账户的密码
	 * @param oldPassword	旧密码
	 * @param newPassword	新密码
	 * @param type  1账户管理私钥 ，2交易私钥
	 * @return Result
	 */
	public Result changeWalletPassword(String oldPassword, String newPassword, int type) {
		//密码位数和难度检测
		if(!validPassword(oldPassword) || !validPassword(newPassword)) {
			return new Result(false, "密码需6位或以上，且包含字母和数字");
		}
		//判断钱包是否加密
		if(!isWalletEncrypted()) {
			return new Result(false, "钱包尚未加密，请使用encryptwallet命令对钱包加密");
		}

		Result rs = decryptWallet(oldPassword);
		if(!rs.isSuccess()){
			return rs;
		}
		int successCount = 0; //成功个数
		//加密钱包

		Result res = encryptWallet(newPassword);
		if(!res.isSuccess()) {
			return res;
		}

		String message = "成功修改账户密码："+res.getMessage();
		return new Result(true, message);
	}

	/**
	 * 加载现有的帐户
	 * @throws IOException
	 */
	public void loadAccount() throws IOException {
		this.accountList.clear();

		File accountDirFile = new File(accountDir);

		if(!accountDirFile.exists() || !accountDirFile.isDirectory()) {
			throw new IOException("account base dir not exists");
		}

		//加载帐户目录下的所有帐户
		Set<String> addresses = new HashSet<String>();
		File[] accountFiles = accountDirFile.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return name.endsWith(".dat");
			}
		});
		List<File> fileList = new ArrayList();
		for(int i = 0;i<accountFiles.length;i++){
			fileList.add(accountFiles[i]);
		}
		Collections.sort(fileList, new Comparator< File>() {
			@Override
			public int compare(File o1, File o2) {
				return o1.getName().toLowerCase().compareTo(o2.getName().toLowerCase());
			}
		});

		for (File accountFile : fileList) {
			if(accountFile.isDirectory()) {
				continue;
			}
			//读取私匙
			FileInputStream fis = new FileInputStream(accountFile);
			try {
				byte[] datas = new byte[fis.available()];
				fis.read(datas);
				int cursor = 0;
				while (cursor<datas.length) {
					Account account = Account.parse(datas,cursor, network);
					if (account == null) {
						log.warn("parse account err, file {}", accountFile);
						continue;
					}
					//验证帐户
					account.verify();
					if(!addresses.contains(account.getAddress().getBase58())) {
						addresses.add(account.getAddress().getBase58());
						accountList.add(account);
					}

					if(log.isDebugEnabled()) {
						log.debug("load account {} success", account.getAddress().getBase58());
					}
					cursor+= account.serialize().length;
				}
			} catch (VerificationException e) {
				log.warn("read account file {} err", accountFile);
				throw e;
			} finally {
				fis.close();
			}

		}
		//判断账户不存在时是否自动创建
		if(accountList.size() == 0 && Configure.ACCOUNT_AUTO_INIT) {
			try {
				createNewAccount();
			} catch (Exception e) {
				log.error("自动初始化账户失败", e);
			}
		}

		//初始化交易数据
		transactionStoreProvider.init();

		//加载账户信息
		List<byte[]> hash160s = getAccountHash160s();

		//初始化账户交易过滤器
		initAccountFilter(hash160s);

		//或许重新加载账户相关的交易记录
		maybeReLoadTransaction(hash160s);

		//加载各地址的余额
		loadBalanceFromChainstateAndUnconfirmedTransaction(hash160s);

		//加载认证账户信息对应的最新的账户信息交易
		loadAccountInfosNewestTransaction();

	}

	//加载认证账户信息对应的最新的交易记录
	private void loadAccountInfosNewestTransaction() {
		for (Account account : accountList) {
			if(account.isCertAccount()) {
				account.setAccountTransaction(transactionStoreProvider.getAccountInfosNewestTransaction(account.getAddress().getHash160()));
			}
		}
	}

	//是否重新加载账户交易
	private void maybeReLoadTransaction(List<byte[]> hash160s) {
		//判断上次加载的和本次的账户是否完全一致
		List<byte[]> hash160sStore = transactionStoreProvider.getAddresses();

		//如果个数一样，则判断是否完全相同
		if(hash160s.size() == hash160sStore.size()) {
			Comparator<byte[]> comparator = new Comparator<byte[]>() {
				@Override
				public int compare(byte[] o1, byte[] o2) {
					return Hex.encode(o1).compareTo(Hex.encode(o2));
				}
			};
			Collections.sort(hash160s, comparator);
			Collections.sort(hash160sStore, comparator);
			boolean fullSame = true;
			for (int i = 0; i < hash160s.size(); i++) {
				if(!Arrays.equals(hash160sStore.get(i), hash160s.get(i))) {
					fullSame = false;
					break;
				}
			}
			if(fullSame) {
				return;
			}
		}
		transactionStoreProvider.reloadTransaction(hash160s);
	}

	//初始化账户交易过滤器
	private void initAccountFilter(List<byte[]> hash160s) {
		blockStoreProvider.initAccountFilter(hash160s);
	}

	//获取账户对应的has160
	private List<byte[]> getAccountHash160s() {
		CopyOnWriteArrayList<byte[]> hash160s = new CopyOnWriteArrayList<byte[]>();
		for (Account account : accountList) {
			Address address = account.getAddress();
			byte[] hash160 = address.getHash160();

			hash160s.add(hash160);
		}
		return hash160s;
	}

	//如果钱包目录不存在则创建
	private void maybeCreateAccountDir() throws IOException {
		//检查账户目录是否存在
		File accountDirFile = new File(accountDir);
		if(!accountDirFile.exists() || !accountDirFile.isDirectory()) {
			accountDirFile.mkdir();
		}
	}

	/*
	 * 从状态链（未花费的地址集合）和未确认的交易加载余额
	 */
	private void loadBalanceFromChainstateAndUnconfirmedTransaction(List<byte[]> hash160s) {

		try {
			for (Account account : accountList) {
				Address address = account.getAddress();
				loadAddressBalance(address);
			}
		}catch (Exception e) {
			log.error(e.getMessage(), e);
		}
	}

	//加载单个地址的余额信息
	private void loadAddressBalance(Address address) {
		//查询可用余额和等待中的余额
		Coin[] balances = transactionStoreProvider.getBalanceAndUnconfirmedBalance(address.getHash160());

		address.setBalance(balances[0]);
		address.setUnconfirmedBalance(balances[1]);
	}

	/**
	 * 获取账户列表，其中包含了余额信息
	 * 如果有冻结余额，那么重新加载一次，因为冻结的余额由可能发生变法
	 * @return List<Account>
	 */
	public List<Account> getAccountList() {
		//如果某个账户有冻结余额，则重新加载
		for (Account account : accountList) {
			Address address = account.getAddress();
			if(address.getUnconfirmedBalance() == null || address.getUnconfirmedBalance().isGreaterThan(Coin.ZERO)) {
				loadAddressBalance(address);
			}
		}
		return accountList;
	}

	public void clearAccountList() {
		accountList.clear();
	}

	/*
	 * 初始化监听器
	 */
	private void initListeners() {
		TransactionListener tl = new TransactionListener() {
			@Override
			public void newTransaction(TransactionStore tx) {

				//更新余额
				loadBalanceFromChainstateAndUnconfirmedTransaction(getAccountHash160s());
				if(transactionListener != null) {
					try {
						transactionListener.newTransaction(tx);
					} catch (Exception e) {
					}
				}
			}
		};
		transactionStoreProvider.setTransactionListener(tl);
	}

	/**
	 * 设置新交易监听器
	 * @param transactionListener
	 */
	public void setTransactionListener(TransactionListener transactionListener) {
		this.transactionListener = transactionListener;
	}

	public TransactionListener getTransactionListener() {
		return transactionListener;
	}

	/**
	 * 设置通知监听器
	 * @param noticeListener
	 */
	public void setNoticeListener(NoticeListener noticeListener) {
		transactionStoreProvider.setNoticeListener(noticeListener);
	}

	/**
	 * 校验密码难度
	 * @param password
	 * @return boolean
	 */
	public static boolean validPassword(String password) {
		if(StringUtils.isEmpty(password)){
			return false;
		}
		if(password.length() < 6){
			return false;
		}
		if(password.matches("(.*)[a-zA-z](.*)") && password.matches("(.*)\\d+(.*)")){
			return true;
		} else {
			return false;
		}
	}

	public boolean accountIsEncrypted() {
		String address = null;
		return accountIsEncrypted(address,Definition.TX_VERIFY_MG);
	}
	/**
	 * @return boolean
	 */
	public boolean accountIsEncrypted(int type) {
		Account account = null;
		return accountIsEncrypted(account,type);
	}


	/*
	* 判断钱包是否加密：
	* return :  true：至少有一个系统账户加密，false：所有系统账户都没有加密
	* */
	public boolean isWalletEncrypted(){
		for(Account account:accountList){
			if(!account.isCertAccount()&&accountIsEncrypted(account,Definition.TX_VERIFY_TR))
				return true;
		}
		return false;
	}

	/**
	 * @param type  1账户管理私钥 ，2交易私钥
	 * @return boolean
	 */
	public boolean accountIsEncrypted(Account account,int type) {
		if(account == null) {
			account = getDefaultAccount();
		}

		if(!account.isCertAccount() && account.isEncrypted()) {
			return true;
		} else if(account.isCertAccount()) {
			if(type == Definition.TX_VERIFY_MG && account.isEncryptedOfMg()) {
				return true;
			} else if(type == Definition.TX_VERIFY_TR && account.isEncryptedOfTr()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param type  1账户管理私钥 ，2交易私钥
	 * @return boolean
	 */
	public boolean accountIsEncrypted(String address,int type) {
		Account account = null;
		if(address!=null){
			account = getAccount(address);
		}
		if(account == null){
			account = getDefaultAccount();
		}
		return accountIsEncrypted(account,type);
	}

	/**
	 * 重新设置账户的私钥
	 */
	public void resetKeys() {
		if(isUnlockedByCmd){
			return;
		}
		for (Account account : accountList) {
			account.resetKey();
		}
	}

	/**
	 * 账户是否是认证账户
	 * @return boolean
	 */
	public boolean isCertAccount() {
		for (Account account : accountList) {
			if(account.isCertAccount()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 获取认证账户列表
	 * @return List<AccountStore>
	 */
	public List<AccountStore> getCertAccounts() {
		return getCertAccounts(null);
	}

	/**
	 * 获取认证账户列表
	 * @param certAccountList   //是否重新获取
	 * @return List<AccountStore>
	 */
	public List<AccountStore> getCertAccounts(List<AccountStore> certAccountList) {
		byte[] certAccounts = chainstateStoreProvider.getBytes(Configure.CERT_ACCOUNT_KEYS);
//		if(certAccountList != null && certAccountList.size() == certAccounts.length / Address.LENGTH) {
//			//没有变化，则直接返回
//			return certAccountList;
//		}
		certAccountList = new ArrayList<AccountStore>();
		if(certAccounts == null) {
			return certAccountList;
		}
		for (int i = 0; i < certAccounts.length; i += Address.LENGTH + Sha256Hash.LENGTH) {
			byte[] hash160 = Arrays.copyOfRange(certAccounts, i, i + Address.LENGTH);
			AccountStore accountStore = chainstateStoreProvider.getAccountInfo(hash160);
			if(accountStore != null) {
				certAccountList.add(accountStore);
			}
		}
		return certAccountList;
	}

	/**
	 * 获取共识账户列表
	 * @return List<AccountStore>
	 */
	public List<AccountStore> getConsensusAccounts() {
		List<ConsensusModel> list = consensusPool.getContainer();
		List<AccountStore> consensusAccountList = new ArrayList<AccountStore>();
		if(list == null) {
			return consensusAccountList;
		}
		for (ConsensusModel consensusModel : list) {
			byte[] hash160 = consensusModel.getApplicant();
			AccountStore accountStore = chainstateStoreProvider.getAccountInfo(hash160);
			if(accountStore == null) {
				continue;
			}
			consensusAccountList.add(accountStore);
		}

		return consensusAccountList;
	}

	/**
	 * 获取自己的账户信息
	 * @return AccountStore
	 */
	public AccountStore getAccountInfo() {
		return getAccountInfo(null);
	}

	/**
	 * 获取自己的账户信息
	 * @param address
	 * @return AccountStore
	 */
	public AccountStore getAccountInfo(String address) throws VerificationException {
		byte[] hash160 = null;
		Address address1 = null;
		if(StringUtil.isEmpty(address)) {
			hash160 = getDefaultAccount().getAddress().getHash160();
		} else {
			try {
				address1 = Address.fromBase58(network, address);
				hash160 = address1.getHash160();
			} catch (Exception e) {
				throw new VerificationException("错误的地址");
			}
		}

		AccountStore accountStore = chainstateStoreProvider.getAccountInfo(hash160);
		if (address1 !=null && address1.getVersion() == network.getCertAccountVersion()&& accountStore  == null){
			throw new VerificationException("账户不存在");
		}
		if(accountStore == null ) {
			accountStore = new AccountStore(network);
			accountStore.setAccountBody(AccountBody.empty());
			accountStore.setCert(0);
			accountStore.setHash160(hash160);
			accountStore.setType(network.getSystemAccountVersion());
			accountStore.setBalance(getBalance().value);
			accountStore.setPubkeys(getDefaultAccount().getMgPubkeys());
		}
		return accountStore;
	}

	/**
	 * 检查当前账户是否在共识中状态
	 * @return boolean
	 */
	public boolean checkIsConsensusingPackager(byte[] hash160) {
		if(accountList == null || accountList.size() == 0) {
			return false;
		}
		if(hash160 != null) {
			return consensusPool.isPackager(hash160);
		}
		for (Account account : accountList) {
			if(consensusPool.isPackager(account.getAddress().getHash160())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 检查当前账户是否在共识中状态
	 * @return boolean
	 */
	public boolean checkConsensusing(byte[] hash160) {
		if(accountList == null || accountList.size() == 0) {
			return false;
		}
		if(hash160 != null) {
			return consensusPool.contains(hash160);
		}
		for (Account account : accountList) {
			if(consensusPool.contains(account.getAddress().getHash160())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 注册成为共识节点
	 * @return Result
	 */
	public Result registerConsensus(String packagerAddress) {
		//选取第一个可注册共识的账户进行广播
		try {
			// 获取最新区块头
			BlockHeader bestBlockHeader = network.getBestBlockHeader();

			// 获取默认账户
			Account account = getDefaultAccount();

			//获取账户存储信息
			AccountStore accountStore = chainstateStoreProvider.getAccountInfo(account.getAddress().getHash160());

			//这里判断默认账户是否为空，并且默认账户的信用值是否大于等于1
			// 同时判断账户是否为空，即没有共识账户 以及信用值为0
			if((accountStore != null && accountStore.getCert() >= ConsensusCalculationUtil.getConsensusCredit(bestBlockHeader.getHeight()))
					|| (ConsensusCalculationUtil.getConsensusCredit(bestBlockHeader.getHeight()) <= 0l && accountStore == null)) {

				//保证金是否充足
				//根据当前人数动态计算参与共识的保证金
				//上下限为1W -- 100W INS
				//当前共识人数
				int currentConsensusSize = bestBlockHeader.getPeriodCount();
				//共识保证金
				Coin recognizance = ConsensusCalculationUtil.calculatRecognizance(currentConsensusSize, bestBlockHeader.getHeight());
				//输入金额
				Coin totalInputCoin = Coin.ZERO;
				//选择输入
				List<TransactionOutput> fromOutputs = selectNotSpentTransaction(recognizance, account.getAddress());
				if(fromOutputs == null || fromOutputs.size() == 0) {
					return new Result(false, "余额不足,不能申请共识;当前共识人数" + currentConsensusSize + ",所需保证金 " + recognizance.toText() + " LCC");
				}
				//是否有指定的打包人
				byte[] packager = null;
				if(packagerAddress == null) {
					packager = getDefaultAccount().getAddress().getHash160();
				} else {
					try {
						Address per = Address.fromBase58(network, packagerAddress);
						packager = per.getHash160();
						//验证信用是否达标
					} catch (Exception e) {
						return new Result(false, "指定共识人不正确");
					}
				}
				RegConsensusTransaction tx = new RegConsensusTransaction(network, Definition.VERSION, bestBlockHeader.getPeriodStartTime(), packager);

				TransactionInput input = new TransactionInput();
				for (TransactionOutput output : fromOutputs) {
					input.addFrom(output);
					totalInputCoin = totalInputCoin.add(Coin.valueOf(output.getValue()));
				}
				//创建一个输入的空签名
				if(account.getAccountType() == network.getSystemAccountVersion()) {
					//普通账户的签名
					input.setScriptSig(ScriptBuilder.createInputScript(null, account.getEcKey()));
				} else {
					//认证账户的签名
					input.setScriptSig(ScriptBuilder.createCertAccountInputScript(null, account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160()));
				}
				tx.addInput(input);

				//输出到脚本
				Script out = ScriptBuilder.createConsensusOutputScript(account.getAddress().getHash160(), network.getCommunityManagerHash160());
				tx.addOutput(recognizance, out);

				//是否找零
				if(totalInputCoin.isGreaterThan(recognizance)) {
					tx.addOutput(totalInputCoin.subtract(recognizance), account.getAddress());
				}
				log.info("共识保证金：{}", recognizance.toText());
				//签名交易
				final LocalTransactionSigner signer = new LocalTransactionSigner();
				try {
					if(account.getAccountType() == network.getSystemAccountVersion()) {
						//普通账户的签名
						signer.signInputs(tx, account.getEcKey());
					} else {
						//认证账户的签名
						signer.signCertAccountInputs(tx, account.getTrEckeys(), account.getAccountTransaction().getHash().getBytes(), account.getAddress().getHash160());
					}
				} catch (Exception e) {
					log.error(e.getMessage(), e);
					BroadcastResult broadcastResult = new BroadcastResult();
					broadcastResult.setSuccess(false);
					broadcastResult.setMessage("签名失败");
					return broadcastResult;
				}
				tx.sign(account);
				tx.verify();
				tx.verifyScript();

				//验证交易
				TransactionValidatorResult valRes = transactionValidator.valDo(tx).getResult();
				if(!valRes.isSuccess()) {
					return new Result(false, valRes.getMessage());
				}

				//加入内存池
				MempoolContainer.getInstace().add(tx);

				BroadcastResult broadcastResult = peerKit.broadcast(tx).get();
				if(broadcastResult.isSuccess()) {
					return new Result(true, "申请共识请求已成功发送到网络,等待网络确认后即可开始共识");
				} else {
					MempoolContainer.getInstace().remove(tx.getHash());
				}
			}

		} catch (Exception e) {
			log.error("共识请求出错", e);
			return new Result(false, "共识请求出错");
		}
		return new Result(false, "没有可参与共识的账户");
	}

	/**
	 * 退出共识
	 * @return Result
	 */
	public Result quitConsensus() {
		//选取共识中的账户进行广播
		try {
			for (Account account : accountList) {
				if(consensusPool.contains(account.getAddress().getHash160())) {
					RemConsensusTransaction remConsensus = new RemConsensusTransaction(network);

					Sha256Hash txhash = consensusPool.getTx(account.getAddress().getHash160());

					Transaction tx = getTransaction(txhash).getTransaction();

					TransactionInput input = new TransactionInput(tx.getOutput(0));
					input.setScriptBytes(new byte[0]);
					remConsensus.addInput(input);

					RegConsensusTransaction regTx = (RegConsensusTransaction) tx;
					int accountType = network.getSystemAccountVersion();
					if(regTx.isCertAccount()) {
						accountType = network.getCertAccountVersion();
					}
					remConsensus.addOutput(Coin.valueOf(tx.getOutput(0).getValue()), new Address(network, accountType, regTx.getHash160()));

					remConsensus.sign(account);

					remConsensus.verify();
					remConsensus.verifyScript();

					//加入内存池
					MempoolContainer.getInstace().add(remConsensus);

					BroadcastResult broadcastResult = peerKit.broadcast(remConsensus).get();
					if(broadcastResult.isSuccess()) {
						//退出当前轮共识所需要的时间
						long time = 0;
						ConsensusMeeting consensusMeeting = SpringContextUtils.getBean(ConsensusMeeting.class);
						MiningInfos miningInfo = consensusMeeting.getMineMiningInfos();
						Date endTime = new Date(miningInfo.getEndTime()*1000);
						Date nowTime = new Date(TimeService.currentTimeMillis());
						time = (endTime.getTime()-nowTime.getTime())/1000;
						if(time < 0) {
							time = 0;
						}
						return new Result(true, "退出共识请求已成功发送到网络,预计"+time+"秒后可真正退出共识");
					} else {
						MempoolContainer.getInstace().remove(remConsensus.getHash());
					}
				}
			}
		} catch (Exception e) {
			log.error("申请退出共识出错", e);
			return new Result(false, e.getMessage());
		}
		return new Result(false, "没有共识中的账户");
	}

	/**
	 * 通过地址获取账户
	 * @param address
	 * @return Account
	 */
	public Account getAccount(String address) {
		for (Account account : accountList) {
			if(account.getAddress().getBase58().equals(address)) {
				return account;
			}
		}
		return null;
	}

	/**
	 * 根据hash160获取用户store信息
	 * @param hash160
	 * @return
	 */
	public AccountStore getAccountStore(byte[] hash160) {
		return chainstateStoreProvider.getAccountInfo(hash160);
	}

	/**
	 * 设置别名
	 * @param alias
	 * @return Result
	 * @throws UnsupportedEncodingException
	 */
	public Result setAlias(String alias) throws UnsupportedEncodingException {
		return setAlias(getDefaultAccount().getAddress().getBase58(), alias);
	}

	/**
	 * 设置别名
	 * @param address
	 * @param alias
	 * @return Result
	 * @throws UnsupportedEncodingException
	 */
	public Result setAlias(String address, String alias) throws UnsupportedEncodingException {
		if(StringUtil.isEmpty(alias)) {
			return new Result(false, "别名不能为空");
		}
		byte[] aliasBytes = alias.getBytes("utf-8");
		if(aliasBytes.length > 30) {
			return new Result(false, "别名不能超过10个汉字或者20个英文与字母");
		}

		//账户信息
		Account account = null;
		if(StringUtil.isEmpty(address)) {
			account = getDefaultAccount();
		} else {
			account = getAccount(address);
		}

		if((account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) ||
				(account.getAccountType() == network.getCertAccountVersion() && account.isEncryptedOfTr())) {
			return new Result(false, "账户已加密");
		}

		AccountStore accountInfo = chainstateStoreProvider.getAccountInfo(account.getAddress().getHash160());
		if(accountInfo == null || accountInfo.getCert() < Configure.REG_ALIAS_CREDIT) {
			return new Result(false, "账户信用达到" + Configure.REG_ALIAS_CREDIT + "之后才能注册别名");
		}
		//是否已经设置过别名了
		byte[] aliasBytesTemp = accountInfo.getAlias();
		if(aliasBytesTemp != null && aliasBytesTemp.length > 0) {
			return new Result(false, "已经设置别名，不能重复设置");
		}
		//别名是否已经存在
		accountInfo = chainstateStoreProvider.getAccountInfoByAlias(aliasBytes);
		if(accountInfo != null) {
			return new Result(false, "该别名已经存在，请换一个");
		}

		RegAliasTransaction regAliasTx = new RegAliasTransaction(network);
		regAliasTx.setAlias(aliasBytes);
		regAliasTx.sign(account);

		try {
			MempoolContainer.getInstace().add(regAliasTx);
			BroadcastResult result = peerKit.broadcast(regAliasTx).get();
			return new Result(result.isSuccess(), result.getMessage());
		} catch (InterruptedException | ExecutionException | TimeoutException e) {
			return new Result(false, "广播过程中出错，可能原因超时：" + e.getMessage());
		}
	}

	/**
	 * 修改别名
	 * @param alias
	 * @return Result
	 * @throws UnsupportedEncodingException
	 */
	public Result updateAlias(String alias) throws UnsupportedEncodingException {
		return updateAlias(getDefaultAccount().getAddress().getBase58(), alias);
	}

	/**
	 * 修改别名
	 * @param address
	 * @param alias
	 * @return Result
	 * @throws UnsupportedEncodingException
	 */
	public Result updateAlias(String address, String alias) throws UnsupportedEncodingException {
		if(StringUtil.isEmpty(alias)) {
			return new Result(false, "别名不能为空");
		}
		byte[] aliasBytes = alias.getBytes("utf-8");
		if(aliasBytes.length > 30) {
			return new Result(false, "别名不能超过10个汉字或者20个英文与字母");
		}

		//账户信息
		Account account = null;
		if(StringUtil.isEmpty(address)) {
			account = getDefaultAccount();
		} else {
			account = getAccount(address);
		}

		if((account.getAccountType() == network.getSystemAccountVersion() && account.isEncrypted()) ||
				(account.getAccountType() == network.getCertAccountVersion() && account.isEncryptedOfTr())) {
			return new Result(false, "账户已加密");
		}

		AccountStore accountInfo = chainstateStoreProvider.getAccountInfo(account.getAddress().getHash160());
		if(accountInfo == null || accountInfo.getCert() < Configure.UPDATE_ALIAS_CREDIT) {
			return new Result(false, "账户信用达到" + Configure.UPDATE_ALIAS_CREDIT + "之后才能修改别名");
		}
		//是否有改动
		byte[] aliasBytesTemp = accountInfo.getAlias();
		if(aliasBytesTemp != null && Arrays.equals(aliasBytesTemp, aliasBytes)) {
			return new Result(false, "别名没有改动");
		}
		//别名是否已经存在
		accountInfo = chainstateStoreProvider.getAccountInfoByAlias(aliasBytes);
		if(accountInfo != null) {
			return new Result(false, "该别名已经存在，请换一个");
		}

		UpdateAliasTransaction updateAliasTx = new UpdateAliasTransaction(network);
		updateAliasTx.setAlias(aliasBytes);
		updateAliasTx.sign(account);

		try {
			MempoolContainer.getInstace().add(updateAliasTx);
			BroadcastResult result = peerKit.broadcast(updateAliasTx).get();
			return new Result(result.isSuccess(), result.getMessage());
		} catch (InterruptedException | ExecutionException | TimeoutException e) {
			return new Result(false, "广播过程中出错，可能原因超时：" + e.getMessage());
		}
	}
}
