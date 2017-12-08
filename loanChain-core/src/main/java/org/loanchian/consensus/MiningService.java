package org.loanchian.consensus;

import org.loanchian.Configure;
import org.loanchian.account.Account;
import org.loanchian.account.Address;
import org.loanchian.core.*;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.filter.BloomFilter;
import org.loanchian.filter.InventoryFilter;
import org.loanchian.kits.AccountKit;
import org.loanchian.kits.PeerKit;
import org.loanchian.mempool.Mempool;
import org.loanchian.mempool.MempoolContainer;
import org.loanchian.message.Block;
import org.loanchian.message.BlockHeader;
import org.loanchian.message.InventoryItem;
import org.loanchian.message.InventoryItem.Type;
import org.loanchian.message.InventoryMessage;
import org.loanchian.msgprocess.TransactionMessageProcess;
import org.loanchian.network.NetworkParams;
import org.loanchian.network.NetworkParams.ProtocolVersion;
import org.loanchian.script.Script;
import org.loanchian.script.ScriptBuilder;
import org.loanchian.service.BlockForkService;
import org.loanchian.service.CreditCollectionService;
import org.loanchian.store.*;
import org.loanchian.transaction.Output;
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

import java.io.IOException;
import java.util.*;

/**
 * 本地打包交易，当被委托时自动执行
 * @author ln
 *
 */
@Service
public final class MiningService implements Mining {
	
	private final static Logger log = LoggerFactory.getLogger(MiningService.class);
	
	private static Mempool mempool = MempoolContainer.getInstace();
	
	@Autowired
	private NetworkParams network;
	@Autowired
	private ConsensusPool consensusPool;
	@Autowired
	private ConsensusMeeting consensusMeeting;
	@Autowired
	private PeerKit peerKit;
	@Autowired
	private AccountKit accountKit;
	@Autowired
	private BlockStoreProvider blockStoreProvider;
	@Autowired
	private ChainstateStoreProvider chainstateStoreProvider;
	@Autowired
	private DataSynchronizeHandler dataSynchronizeHandler;
	@Autowired
	private TransactionValidator transactionValidator;
	@Autowired
	private InventoryFilter filter;
	@Autowired
	private CreditCollectionService creditCollectionService;
	@Autowired
	private BlockForkService blockForkService;
	@Autowired
	private TransactionMessageProcess transactionMessageProcess;

	//运行状态
	private boolean runing;
	//强制停止状态，在打包过程中检查该参数,默认为0，当为1时进入强制停止状态，为2时代表打包已停止
	private int forcedStopModel;
	
	private Account account;
	
	/**
	 * 立刻停止打包，注意不是停止服务
	 */
	public void stopMining() {
		//进入强制停止模式
		forcedStopModel = 1;
		
		//异步监控超时处理
		new Thread() {
			public void run() {
				//超时处理
				long nowTime = TimeService.currentTimeMillis();
				while(true) {
					if(forcedStopModel == 2) {
						break;
					}
					if(TimeService.currentTimeMillis() - nowTime > Configure.BLOCK_GEN__MILLISECOND_TIME) {
						forcedStopModel = 2;
						break;
					}
					try {
						Thread.sleep(100);
					} catch (InterruptedException e) {
						if(log.isDebugEnabled()) {
							log.debug("{}", e.getMessage());
						}
					}
				}
			};
		}.start();
	}
	
	/**
	 * 执行打包
	 */
	public void mining() {
		
		long beginTime = TimeService.currentTimeMillis();
		
		//临时处理，延迟1s，解决内存池来不及移除新块交易的问题
		try {
			Thread.sleep(1000l);
		} catch (InterruptedException e) {
			if(log.isDebugEnabled()) {
				log.debug("{}", e.getMessage());
			}
		}
		log.info("开始打包 , 本地内存交易数量 {}", MempoolContainer.getInstace().getTxCount());
		
		//被打包的交易列表
		List<Transaction> transactionList = new ArrayList<Transaction>();
		
		Coin fee = Coin.ZERO;
		
		//博隆过滤器，检查本次打包的交易是否有双花嫌疑
		BloomFilter inputFilter = new BloomFilter(100000, 0.0001, RandomUtil.randomLong());
		
		int txsSize = 0;
		int maxTxsSize = Definition.MAX_BLOCK_SIZE - 10000;

		while (true) {
			//每次获取内存里面的一个交易
			Transaction tx = null;
			
			while((tx = mempool.get()) != null) {
				if(txsSize > maxTxsSize) {
					break;
				}
				//如果某笔交易验证失败，则不打包进区块
				try{
					//去除重复交易
					if(transactionList.contains(tx)) {
						break;
					}
					boolean res = verifyTx(transactionList, tx, inputFilter, true);
					if(res) {
						//交易费
						//只有pay交易才有交易费
						if(tx.isPaymentTransaction()) {
							fee = fee.add(getTransactionFee(tx));
						}
						transactionList.add(tx);

						txsSize += tx.getLength();
					} else {
						//验证失败
						debug("交易验证失败：" + tx.getHash());
					}
				} catch (Exception e) {
					log.error("交易验证失败：{}", tx.getHash());
					debug("交易验证失败：" + tx.getHash() + "    错误详情：" + e.getMessage());
				}
				
				//如果时间到了，那么退出打包，然后广区块
				if(TimeService.currentTimeMillis() - beginTime >= Configure.BLOCK_GEN__MILLISECOND_TIME || forcedStopModel == 1) {
					break;
				}
			}
			//如果时间到了，那么退出打包，然后广区块
			if(TimeService.currentTimeMillis() - beginTime >= Configure.BLOCK_GEN__MILLISECOND_TIME || forcedStopModel == 1) {
				break;
			}

			try {
				Thread.sleep(50l);
			} catch (InterruptedException e) {
				if(log.isDebugEnabled()) {
					log.debug("{}", e.getMessage());
				}
			}
		}

		//在这里对transactionList的资产转账交易做特殊处理
 		this.verifyAssetsTx(transactionList);

		//获取我的时段开始时间
		MiningInfos miningInfos = consensusMeeting.getMineMiningInfos();

		//本地最新区块
		BlockHeader bestBlockHeader = blockStoreProvider.getBestBlockHeader().getBlockHeader();
		
		long currentHeight = bestBlockHeader.getHeight() + 1;
		//coinbase交易
		//coinbase交易获取手续费
		Transaction coinBaseTx = new Transaction(network);
		coinBaseTx.setVersion(Definition.VERSION);
		coinBaseTx.setType(Definition.TYPE_COINBASE);
		coinBaseTx.setLockTime(currentHeight + Configure.MINING_MATURE_COUNT);	//冻结区块数
		
		TransactionInput input = new TransactionInput();
		coinBaseTx.addInput(input);
		input.setScriptSig(ScriptBuilder.createCoinbaseInputScript("this a gengsis tx".getBytes()));
		
		//获得当前高度的奖励
		Coin consensusRreward = ConsensusCalculationUtil.calculatReward(currentHeight);

		//奖励发放给委托人
		byte[] hash160 = miningInfos.getCommissioned();

		if(Arrays.equals(account.getAddress().getHash160(), hash160)) {
			coinBaseTx.addOutput(fee.add(consensusRreward), account.getAddress());
		} else {
			AccountStore accountStore = chainstateStoreProvider.getAccountInfo(hash160);
			coinBaseTx.addOutput(fee.add(consensusRreward), new Address(network, accountStore.getType(), accountStore.getHash160()));
		}
		coinBaseTx.verify();
		
		//加入coinbase交易到交易列表
		transactionList.add(0, coinBaseTx);
		
		//处理违规情况的节点，目前只处理超时的
		Set<TimeoutConsensusViolation> timeoutList = consensusMeeting.getTimeoutList();

		if(consensusMeeting.getCurrentMeetingPeriodCount() > 7) {
			for (TimeoutConsensusViolation consensusViolation : timeoutList) {
				log.info("超时的节点： {} , currentPeriodStartTime: {} , previousPeriodStartTime: {}" , new Address(network, consensusViolation.getHash160()).getBase58(), DateUtil.convertDate(new Date(consensusViolation.getCurrentPeriodStartTime() * 1000)), DateUtil.convertDate(new Date(consensusViolation.getPreviousPeriodStartTime() * 1000)));
				//判断该节点是否已被处理，如果没处理则我来处理
				processViolationConsensusAccount(ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK, consensusViolation, transactionList, inputFilter);
			}
		}

		//遵守系统规则，如果出现特殊情况，当前网络时间超过了我的时段，停止广播，等待处罚
		if(miningInfos.getEndTime() + Configure.BLOCK_GEN_TIME / 2 < TimeService.currentTimeSeconds() ) {
			log.info("打包高度为 {} 的块时超时，停止广播，我的开始时间{}, 结束时间{}, 当前时间{}", currentHeight, DateUtil.convertDate(new Date(miningInfos.getBeginTime() * 1000)), DateUtil.convertDate(new Date(miningInfos.getEndTime() * 1000)), DateUtil.convertDate(new Date(TimeService.currentTimeMillis())));
			return;
		}
		
		//广播区块
		Block block = new Block(network);

		block.setHeight(currentHeight);
		block.setPreHash(bestBlockHeader.getHash());
		block.setTime(miningInfos.getEndTime());
		block.setVersion(network.getProtocolVersionNum(ProtocolVersion.CURRENT));
		block.setTxs(transactionList);
		block.setPeriodCount(miningInfos.getPeriodCount());
		block.setTimePeriod(miningInfos.getTimePeriod());
		block.setPeriodStartTime(miningInfos.getPeriodStartTime());
		
		verifyBlockTx(block);
		
		block.setTxCount(transactionList.size()); 
		block.setMerkleHash(block.buildMerkleHash());
		
		block.sign(account);
		
		block.verify();
		
		block.verifyScript();
		
		BlockStore blockStore = new BlockStore(network, block);

		try {

			log.info("高度 {} , 出块时间 {} , 交易数量 {} , 手续费 {} , 内存交易数 {},块长度{}", block.getHeight(), DateUtil.convertDate(new Date(block.getTime() * 1000)), transactionList.size(), fee, MempoolContainer.getInstace().getTxCount(),txsSize);
			if(log.isDebugEnabled()) {
				log.debug("高度 {} , 出块时间 {} , 交易数量 {} , 手续费 {} ", block.getHeight(), DateUtil.convertDate(new Date(block.getTime())), transactionList.size(), fee);
			}
			//是否被强制停止了
			if(forcedStopModel == 1) {
				 enterForcedStopModel(transactionList);
				 log.info("=======================================");
				 log.info("=============被强行停止了，不广播=============");
				 log.info("=======================================");
				 return;
			}
			
			//分叉处理 TODO
			
			blockStoreProvider.saveBlock(blockStore);
			if(log.isDebugEnabled()) {
				log.debug("broadcast new block hash {}, height {}, tx size {}, merkle hash {}", blockStore.getBlock().getHash(), blockStore.getBlock().getHeight(),
						blockStore.getBlock().getTxs().size(), blockStore.getBlock().getMerkleHash());
			}
			
			blockStore = blockStoreProvider.getBlockByHeight(block.getHeight());
			
			//广播
			InventoryItem item = new InventoryItem(Type.NewBlock, block.getHash());
			InventoryMessage invMessage = new InventoryMessage(network, item);

			int broadcastCount = (Configure.IS_SUPER_NODE==1)?Configure.MAX_SUPER_CONNECT_COUNT:Configure.MAX_NORMAL_BROADCAST_SUPER_CONNECT_COUNT;
			if(block.getLength()>Definition.MIN_BLOCK_SIZE && (Configure.IS_SUPER_NODE == 0)) {
				peerKit.broadcastMessageToSuper(invMessage, broadcastCount);
			}else{
				peerKit.broadcastMessage(invMessage);
			}
			
			//加入Inv过滤列表
			filter.insert(block.getHash().getBytes());
			
			if(peerKit.getBlockChangedListener() != null) {
				peerKit.getBlockChangedListener().onChanged(block.getHeight(), block.getHeight(), block.getHash(), block.getHash());
			}
		} catch (IOException e) {
			log.error("共识产生的新块保存时报错", e);
		}
	}

	/**
	 * 这里对资产转让交易做特殊处理
	 * 为了防止同一账户在一次共识中针对同一个资产重复提交多次转账交易，
	 * 从而导致总金额已经超过了账户上该资产的余额，
	 * 出现此情况时，过滤掉超出金额的那部分交易
	 * @param list
	 */
	private void verifyAssetsTx(List<Transaction> list) {
		if (list == null || list.size() == 0) {
			return;
		}

		//此map的结构 Map<账户id, Map<资产id, 对应交易 >>
		Map<String,Map<String, List<AssetsTransferTransaction>>> map = new HashMap<>();
		AssetsTransferTransaction transferTx;
		AssetsRegisterTransaction registerTx;
		//循环所有交易，将转账交易按照map结构，存放进去
		for(Transaction tx : list) {
			if(tx instanceof AssetsTransferTransaction) {
				//找到资产转让交易
				transferTx = (AssetsTransferTransaction)tx;
				//找到对应的注册资产
				TransactionStore txs =  blockStoreProvider.getTransaction(transferTx.getAssetsHash().getBytes());
				registerTx = (AssetsRegisterTransaction)txs.getTransaction();

				//生成账户id
				String userKey = new String(transferTx.getHash160(), Utils.UTF_8);
				//生成资产id，用资产code作为key
				String txKey = new String(registerTx.getCode());

				if(!map.containsKey(userKey)) {
					//如果map里不包含用户，则直接新增
					Map<String,List<AssetsTransferTransaction>> txMap = new HashMap<>();
					List<AssetsTransferTransaction> transferList = new ArrayList<>();
					transferList.add(transferTx);
					txMap.put(txKey, transferList);
					map.put(userKey, txMap);
				}else {
					//如果用户存在则判断当前交易是否已存在同样的资产注册交易
					Map<String,List<AssetsTransferTransaction>> txMap = map.get(userKey);
					if(txMap.containsKey(txKey)) {
						//存在则直接新增
						txMap.get(txKey).add(transferTx);
					}else {
						List<AssetsTransferTransaction> transferList = new ArrayList<>();
						transferList.add(transferTx);
						txMap.put(txKey, transferList);
					}
				}
			}
		}
		//循环每一个用户的资产交易集合，判断每一个资产的交易总额是否大于用户余额，
		//如果大于则在总的交易列表里删除该超出金额的交易，让其作废
		for (Map.Entry<String,Map<String, List<AssetsTransferTransaction>>> entry : map.entrySet()) {
			Map<String, List<AssetsTransferTransaction>> txMap = entry.getValue();
			for(Map.Entry<String, List<AssetsTransferTransaction>> txEntry : txMap.entrySet()) {
				byte[] txKey = txEntry.getKey().getBytes();
				//根据userKey和txkey找到对应的账户
				//求和交易总金额
				List<AssetsTransferTransaction> txList = txEntry.getValue();
				byte[] userKey = txList.get(0).getHash160();
				Assets assets = chainstateStoreProvider.getMyAssetsByCode(userKey, Sha256Hash.hash(txKey));
				long sum = 0;
				for(AssetsTransferTransaction tx : txList) {
					if(sum <= assets.getBalance()) {
						sum += tx.getAmount();
					}
					if(sum > assets.getBalance()) {
						sum = sum - tx.getAmount();
						list.remove(tx);
					}
				}
			}
		}
	}
	
	private void verifyBlockTx(Block block) {
		List<Transaction> txs = block.getTxs();
		
		//被退回的手续费
		Coin refunedFee = Coin.ZERO;

		List<CreditTransaction> creditTxs = new ArrayList<CreditTransaction>();
		
		//已发放的账户，不能在同一区块多次发放
		Set<String> creditAccounts = new HashSet<String>();
		
		Iterator<Transaction> it = txs.iterator();
		while(it.hasNext()) {
			Transaction tx = it.next();
			if(tx.getType() == Definition.TYPE_COINBASE) {
				continue;
			}
			if(verifyTx(txs, tx, null, false)) {
				if(tx.getType() != Definition.TYPE_PAY) {
					continue;
				}
				//发放信用
				//每笔交易有多个输入，根据系统的单账户模式设计，只发放给第一个
				try {
					TransactionInput input = tx.getInput(0);
					Script script = input.getFromScriptSig();
					
					byte[] hash160 = script.getPubKeyHash();
					String hash160AsHex = Hex.encode(hash160);
					
					if(creditCollectionService.verification(Definition.CREDIT_TYPE_PAY, hash160, block.getTime()) && !creditAccounts.contains(hash160AsHex)) {
						CreditTransaction creditTx = new CreditTransaction(network, hash160, Configure.CERT_CHANGE_PAY, Definition.CREDIT_TYPE_PAY, tx.getHash());
						creditTx.sign(account);
						creditTxs.add(creditTx);
						creditAccounts.add(hash160AsHex);
					}
				} catch (Exception e) {
					log.error("发放信用出错", e);
				}
			} else {
				log.error("再次验证失败，移除交易： {} ", tx);
				it.remove();
				if(tx.isPaymentTransaction()) {
					//有金额的交易，计算该笔的手续费
					refunedFee = refunedFee.add(getTransactionFee(tx));
				}
			}
		}
		if(creditTxs.size() > 0) {
			txs.addAll(creditTxs);
		}
		if(refunedFee.isGreaterThan(Coin.ZERO)) {
			Transaction coinbaseTx = txs.get(0);
			TransactionOutput coinbaseOutput = (TransactionOutput)coinbaseTx.getOutput(0);
			coinbaseOutput.setValue(coinbaseOutput.getValue() - refunedFee.value);
			coinbaseTx.setHash(null);
		}
		
		try {
			//处理严重违规的情况
			processSeriousViolation(txs);
		} catch (Exception e) {
			log.error("处理严重违规的情况出错", e);
		}
	}

	/*
	 * 处理严重违规的块，对应的账户
	 */
	private void processSeriousViolation(List<Transaction> transactionList) {
		//严重违规处罚
		List<BlockHeader> evidenceList = blockForkService.getAndRemovePenalize();
		if(evidenceList == null || evidenceList.size() != 2) {
			return;
		}
		//验证证据的合法性
		//违规证据
		BlockHeader blockHeader1 = evidenceList.get(0);
		BlockHeader blockHeader2 = evidenceList.get(1);
		byte[] audienceHash160 = blockHeader1.getHash160();
		if(!Arrays.equals(blockHeader1.getHash160(), blockHeader2.getHash160())) {
			log.warn("违规证据里的两个块打包人不相同");
			return;
		}
		if(blockHeader1.getPeriodStartTime() != blockHeader2.getPeriodStartTime()) {
			log.warn("违规证据里的两个块时段不相同");
			return;
		}
		//验证签名
		try {
			blockHeader1.verifyScript();
			blockHeader2.verifyScript();
		} catch (Exception e) {
			log.warn("违规证据里的两个块验证签名不通过");
			return;
		}
		
		//验证通过
		RepeatBlockViolationEvidence evidence = new RepeatBlockViolationEvidence(audienceHash160, evidenceList);
		//判断该节点是否已经被处理过了
		Sha256Hash evidenceHash = evidence.getEvidenceHash();
		byte[] txHashBytes = chainstateStoreProvider.getBytes(evidenceHash.getBytes());
		if(txHashBytes != null) {
			log.warn("违规证据已经处理了,无需重复处理");
			return;
		}
		
		ViolationTransaction vtx = new ViolationTransaction(network, evidence);
		
		Sha256Hash txhash = consensusPool.getTx(audienceHash160);
		if(txhash == null) {
			log.warn("违规节点共识注册交易没有找到");
			return;
		}
		
		TransactionStore txs = blockStoreProvider.getTransaction(txhash.getBytes());
		if(txs.getHeight() == 0l) {
			return;
		}
		Transaction crtx = txs.getTransaction();
		
		RegConsensusTransaction consensusRegTx = (RegConsensusTransaction) crtx;
		TransactionOutput output = consensusRegTx.getOutput(0);
		byte[] key = output.getKey();
		//本输入在 transactionList 里面不能有2笔对此的引用，否则就造成了双花
		if(filter != null) {
			if(filter.contains(key)) {
				return;
			} 
			filter.insert(key);
		}
		
		//因为违规证据有可能不一样，如果已经被处理过了，则不重复处理，这里用注册共识时的保证金是否被花费掉了来判断
		byte[] status = chainstateStoreProvider.getBytes(key);
		if(status == null || !Arrays.equals(status, new byte[] { 1 })) {
			log.warn("违规节点已经被处理过了，不再重复处理");
			return;
		}
		
		//签名脚本
		Script scriptSig = output.getScript();
		Address address = new Address(network, network.getSystemAccountVersion(), scriptSig.getChunks().get(1).data);
		TransactionInput input = new TransactionInput(output);
		input.setScriptBytes(new byte[0]);
		vtx.addInput(input);
		//输出到保证金没收账户
		vtx.addOutput(Coin.valueOf(output.getValue()), address);
		
		vtx.sign(account);
		vtx.verify();
		vtx.verifyScript();
		
		transactionList.add(vtx);
	}
	
	/*
	 * 强制停止打包，把交易加回内存池
	 */
	private void enterForcedStopModel(List<Transaction> transactionList) {
		try {
			if(transactionList == null || transactionList.size() <= 1) {
				return;
			}
			for (int i = 1; i < transactionList.size(); i++) {
				mempool.add(transactionList.get(i));
			}
		} finally {
			forcedStopModel = 2;
		}
	}

	/*
	 * 处理违规节点
	 * violationType 违规类型，不同的类型面临的处罚不一样，1代表超时未出块
	 */
	private void processViolationConsensusAccount(int violationType, TimeoutConsensusViolation consensusViolation,
			List<Transaction> transactionList, BloomFilter inputFilter) {
		try {
			if(violationType == ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK) {
				//超时处理
				NotBroadcastBlockViolationEvidence evidence = new NotBroadcastBlockViolationEvidence(consensusViolation.getHash160(), 
						consensusViolation.getCurrentPeriodStartTime(), consensusViolation.getPreviousPeriodStartTime());
				//判断该节点是否已经被处理过了
				Sha256Hash evidenceHash = evidence.getEvidenceHash();
				byte[] txHashBytes = chainstateStoreProvider.getBytes(evidenceHash.getBytes());
				if(txHashBytes != null) {
					return;
				}
				
				ViolationTransaction tx = new ViolationTransaction(network, evidence);
				
				Sha256Hash txhash = consensusPool.getTx(consensusViolation.getHash160());
				if(txhash == null) {
					log.warn("违规节点共识注册交易没有找到");
					return;
				}
				
				TransactionStore txs = blockStoreProvider.getTransaction(txhash.getBytes());
				if(txs.getHeight() == 0l) {
					return;
				}
				Transaction crtx = txs.getTransaction();
				
				RegConsensusTransaction consensusRegTx = (RegConsensusTransaction) crtx;
				TransactionOutput output = consensusRegTx.getOutput(0);
				byte[] key = output.getKey();
				//本输入在 transactionList 里面不能有2笔对此的引用，否则就造成了双花
				if(filter != null) {
					if(filter.contains(key)) {
						throw new VerificationException("同一块多个交易引用了同一个输入");
					} 
					filter.insert(key);
				}
				
				//签名脚本
				Script scriptSig = consensusRegTx.getScriptSig();
				Address address = scriptSig.getAccountAddress(network);
				TransactionInput input = new TransactionInput(output);
				input.setScriptBytes(new byte[0]);
				tx.addInput(input);
				tx.addOutput(Coin.valueOf(output.getValue()), address);
				
				tx.sign(account);
				
				tx.verify();
				tx.verifyScript();
				
				transactionList.add(tx);
			}
		} catch (Exception e) {
			log.error("处理违规节点时出错：{}", e.getMessage(), e);
		}
	}

	/*
	 * 获取交易的手续费
	 */
	private Coin getTransactionFee(Transaction tx) {
		Coin inputFee = Coin.ZERO;
		
		List<TransactionInput> inputs = tx.getInputs();
		for (TransactionInput input : inputs) {
			List<TransactionOutput> froms = input.getFroms();
			if(froms == null || froms.size() == 0) {
				continue;
			}
			for (TransactionOutput from : froms) {
				inputFee = inputFee.add(Coin.valueOf(from.getValue()));
			}
		}
		
		Coin outputFee = Coin.ZERO;
		List<TransactionOutput> outputs = tx.getOutputs();
		for (Output output : outputs) {
			outputFee = outputFee.add(Coin.valueOf(output.getValue()));
		}
		return inputFee.subtract(outputFee);
	}

	/*
	 * 验证交易的合法性
	 * @param transactionList	//本次已打包的交易列表
	 * @param tx				//本次打包的交易
	 * @param filter			//布隆过滤器，判断输入是否重复引用
	 * @param forcedCheck		//是否强制检查
	 * @return boolean
	 */
	private boolean verifyTx(List<Transaction> transactionList, Transaction tx, BloomFilter filter, boolean forcedCheck) {
		long time = System.currentTimeMillis();
		try {
			tx.verify();
			
			//信用累积交易，不是从内存里面来的，所以不打包
			if(tx.getType() == Definition.TYPE_CREDIT || tx.getType() == Definition.TYPE_COINBASE) {
				return false;
			}
			if(tx.isPaymentTransaction()) {
				//交易的txid不能和区块里面的交易重复
				TransactionStore verifyTX = blockStoreProvider.getTransaction(tx.getHash().getBytes());
				if(verifyTX != null) {
					throw new VerificationException("交易hash与区块里的重复 " + tx.getHash());
				}
				
				//验证交易的输入来源，是否已花费的交易，同时验证金额
				Coin txInputFee = Coin.ZERO;
				Coin txOutputFee = Coin.ZERO;

				//交易引用的输入，赎回脚本必须一致
				byte[] scriptBytes = null;

				//验证本次交易的输入
				List<TransactionInput> inputs = tx.getInputs();
				int i=0;
				for (TransactionInput input : inputs) {

					scriptBytes = null;

					if (input.getFroms() == null || input.getFroms().size() == 0) {
						continue;
					}
					List<TransactionOutput> froms = input.getFroms();

					if (froms == null || froms.size() == 0) {
						throw new VerificationException("转账交易空的输出");
					}

					for (TransactionOutput from : froms) {
						//对上一交易的引用以及索引值
						Transaction fromTx = from.getParent();
						Sha256Hash fromId = fromTx.getHash();
						int index = from.getIndex();

						byte[] key = from.getKey();

						if (from.getParent().getOutputs() == null || from.getParent().getOutputs().size() == 0 || forcedCheck) {
							//查询上次的交易
							Transaction preTransaction = null;

							//判断是否未花费
							byte[] state = chainstateStoreProvider.getBytes(key);
							if (state == null || state.length == 0) {
								//链上没有该笔交易，这时有两种情况，第一确实是伪造交易，第二花费了没有确认的交易
								//对于第一种情况，验证不通过
								//第二种情况，我们顺序打包交易，也就是引用的输出必须是本次已打包的，否则就扔回内存池

								//首先判断是否已打包
								boolean hasPackage = false;
								for (Transaction transaction : transactionList) {
									if (transaction.getHash().equals(fromId)) {
										preTransaction = transaction;
										hasPackage = true;
										break;
									}
								}
								//已打包就通过
								if (!hasPackage) {
									//没打包，判断内存里面是否存在
									preTransaction = MempoolContainer.getInstace().get(fromId);
									if (preTransaction == null) {
										throw new VerificationException("引用了不存在或不可用的交易");
									} else {
										//在内存池里面，那么就把本笔交易扔回内存池，等待下次打包
//										MempoolContainer.getInstace().add(tx);
										throw new VerificationException("该交易打包顺序不对");
									}
								}
							} else if (Arrays.equals(state, new byte[]{1})) {
								//查询上次的交易
								TransactionStore txs = blockStoreProvider.getTransaction(fromId.getBytes());
								if (txs == null) {
									throw new VerificationException("引用了不存在的交易");
								}
								preTransaction = txs.getTransaction();
							} else {
								//已花费的交易
								throw new VerificationException("引用了已花费的交易");
							}
							TransactionOutput preOutput = preTransaction.getOutput(index);
							from.setValue(preOutput.getValue());
							from.setParent(preTransaction);
						}
						TransactionOutput preOutput = from.getParent().getOutput(index);
						txInputFee = txInputFee.add(Coin.valueOf(preOutput.getValue()));

						//验证交易赎回脚本必须一致
						if (scriptBytes == null) {
							scriptBytes = preOutput.getScriptBytes();
						} else if (!Arrays.equals(scriptBytes, preOutput.getScriptBytes())) {
							throw new VerificationException("错误的输入格式，不同的交易赎回脚本不能合并");
						}

						//本输入在 transactionList 里面不能有2笔对此的引用，否则就造成了双花
						if (filter != null) {
							if (filter.contains(key)) {
								throw new VerificationException("同一块多个交易引用了同一个输入");
							}
							filter.insert(key);
						}
					}
				}

				return true;
			}
			ValidatorResult<TransactionValidatorResult> res = transactionValidator.valDo(tx, transactionList);
			//如果该交易是资产转让交易，需要特殊处理
			if(!(tx instanceof AssetsTransferTransaction)) {
				return res.getResult().isSuccess();
			}
			if(res.getResult().isSuccess() == false) {
				return false;
			}

			//如果一个账户再一轮共识中同时发起了多笔转账交易，则需要验证
			return res.getResult().isSuccess();
		} catch (Exception e) {
			log.warn(e.getMessage(), e);
			return false;
		} finally {
			//System.out.println("验证交易 {} "+tx.getHash()+" 耗时："+(System.currentTimeMillis() - time)+"ms");
		}
	}

	@Override
	public void start() {
		
		runing = true;
		
		//连接到其它节点之后，开始进行共识，如果没有连接，那么等待连接
		while(true && runing) {
			//是否可进行广播，并且本地区块已经同步到最新，并且钱包没有加密
			if(peerKit.canBroadcast() && dataSynchronizeHandler.hasComplete()) {
				consensusMeeting.startSyn();
				reset(false);
				break;
			} else {
				try {
					Thread.sleep(1000l);
				} catch (InterruptedException e) {
					log.error("wait connect err", e);
				}
			}
		}
	}
	
	@Override
	public void stop() {
		runing = false;
		//强制停止
		consensusMeeting.stop();
	}
	
	/**
	 * 重置共识
	 * @param stopNow 如果正在共识，是否马上停止
	 */
	@Override
	public void reset(boolean stopNow) {
		new Thread() {
			public void run() {
				
				if(stopNow) {
					//马上停止打包
					stopMining();
				}
				
				consensusMeeting.setAccount(null);
				while(runing) {
					try {
						Thread.sleep(1000l);
					} catch (InterruptedException e) {
						if(log.isDebugEnabled()) {
							log.debug("{}", e.getMessage());
						}
					}
					//监控自己是否成功成为共识节点
					Account account = accountKit.getDefaultAccount();
					if(account == null) {
						continue;
					}
					if(consensusPool.contains(account.getAddress().getHash160())) {
						//账户是否已解密
						if(!((account.isCertAccount() && account.isEncryptedOfTr()) || 
								(!account.isCertAccount() && account.isEncrypted()))
								&& peerKit.canBroadcast() && dataSynchronizeHandler.hasComplete()) {
							try {
								log.info("开始共识：{}", network.getBestBlockHeight());
								MiningService.this.account = account.clone();
								//放到consensusMeeting里面的账户，去掉密钥，因为里面用不到，这是为了安全
								Account tempAccount = account.clone();
								tempAccount.setMgEckeys(null);
								tempAccount.setTrEckeys(null);
								tempAccount.setEcKey(null);
								consensusMeeting.setAccount(tempAccount);
								consensusMeeting.resetCurrentMeetingItem();
							} catch (CloneNotSupportedException e) {
								log.error("初始化共识时，设置共识账户出错:", e);
							}
							break;
						}
					}
				}
			};
		}.start();
	}
	
	@Override
	public int status() {
		return 0;
	}

	private void debug(String debugMsg) {
		if(log.isDebugEnabled()) {
			log.debug(debugMsg);
		}
	}
}
