package org.loanchian.validator;

import org.loanchian.Configure;
import org.loanchian.consensus.ConsensusInfos;
import org.loanchian.consensus.ConsensusMeeting;
import org.loanchian.core.*;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.message.Block;
import org.loanchian.message.BlockHeader;
import org.loanchian.network.NetworkParams;
import org.loanchian.service.BlockForkService;
import org.loanchian.service.CreditCollectionService;
import org.loanchian.store.BlockHeaderStore;
import org.loanchian.store.BlockStoreProvider;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.TransactionInput;
import org.loanchian.transaction.TransactionOutput;
import org.loanchian.transaction.business.CreditTransaction;
import org.loanchian.utils.ConsensusCalculationUtil;
import org.loanchian.utils.DateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * 新区块验证器
 * @author ln
 *
 */
@Service
public class BlockValidator {

	//区块高度错误
	public final static int ERROR_CODE_HEIGHT_ERROR = 1;
	
	private Logger log = LoggerFactory.getLogger(getClass());
	
	@Autowired
	private ConsensusMeeting consensusMeeting;
	@Autowired
	private NetworkParams networkParams;
	@Autowired
	private BlockStoreProvider blockStoreProvider;
	@Autowired
	private BlockForkService blockForkService;
	@Autowired
	private TransactionValidator transactionValidator;
	@Autowired
	private CreditCollectionService creditCollectionService;

	public Result doVal(Block block) {
		try {
			
			//验证新区块打包的人是否合法
			ConsensusInfos currentInfos = consensusMeeting.getCurrentConsensusInfos(block.getPeriodStartTime(), block.getTimePeriod());

			if(currentInfos == null) {
				log.error("验证新区块时段出错 {} , {}", block.getPeriodStartTime(), block.getTimePeriod());
				return new Result(false, "验证新区块时段出错");
			}
			
			if(log.isDebugEnabled()) {
				log.debug("新区块验证信息：{}", currentInfos);
			}
			
			//如果返回的是不确定，则通过
			if(currentInfos.getResult() == ConsensusInfos.RESULT_UNCERTAIN) {
				log.warn("不确定的时段, {}", block);
				return new Result(false, "uncertain");
			}
			
			if(currentInfos.getPeriodCount() != block.getPeriodCount()) {
				log.error("区块的时段人数和当前轮次人数不一致，不合法的区块, {}", block);
				return new Result(false, "区块的时段人数和当前轮次人数不一致，不合法的区块");
			}
			
			if(!Arrays.equals(currentInfos.getHash160(), block.getHash160())) {
				log.error("新区块打包人验证错误 : {} {}", block.getHeight(), block.getHash());
				return new Result(false, "新区块打包人验证错误");
			}
			
			//如果时间不同，则应该放入分叉里
			if(currentInfos.getBeginTime() > block.getTime() || currentInfos.getEndTime() < block.getTime()) {
				log.error("新区块时间戳验证出错 : 高度 {} , hash {} , 块时间 {}, 时段 {} - {}", block.getHeight(), block.getHash(),
						DateUtil.convertDate(new Date(block.getTime() * 1000)), DateUtil.convertDate(new Date(currentInfos.getBeginTime() * 1000)), DateUtil.convertDate(new Date(currentInfos.getEndTime() * 1000)));
				return new Result(false, "新区块时间戳验证出错");
			}
			
			//允许块的时间和当前时间不超过1个时段的误差，否则验证不通过
			//这个条件的判断，会导致时间不准的节点出错，但是不判断则会给系统带来极大风险，是否放宽条件？  TODO
			long timeDiff = TimeService.currentTimeSeconds() - (block.getPeriodStartTime() + (block.getTimePeriod() + 1) * Configure.BLOCK_GEN_TIME);
			if(Math.abs(timeDiff) > 6 * Configure.BLOCK_GEN_TIME) {
				return new Result(false, "新区块时间误差过大，拒绝接收");
			}

			//节点之间存在一定的时间误差，容忍提前3秒出块
			if(block.getTime() - TimeService.currentTimeSeconds()>3){
				return new Result(false,"提前出块，拒绝接收");
			}

			BlockHeader bestBlock = networkParams.getBestBlockHeader();
			if(bestBlock.getPeriodStartTime() == block.getPeriodStartTime() && (bestBlock.getTimePeriod() - block.getTimePeriod() > 0)) {
				return new Result(false, "新区块时段比老区块小，禁止接收");
			}
			
		} catch (Exception e) {
			log.error("验证新区块时段出错", e);
			return new Result(false, "验证新区块出错," + e.getMessage());
		}
		return new Result(true, "ok");
	}
	
	/**
	 * 验证区块的合法性，如果验证不通过，则抛出验证异常
	 * @param block
	 * @return boolean
	 */
	public Result verifyBlock(Block block) {
		long now = System.currentTimeMillis();
		
		try {
			if(!block.verify()) {
				return new Result(false);
			}
		} catch (VerificationException e) {
			return new Result(false, e.getMessage());
		}
		//验证区块签名
		try {
			block.verifyScript();
		} catch (Exception e) {
			return new Result(false, "签名错误");
		}
		
		//验证区块的交易是否正确
		if(block.getTxCount() != block.getTxs().size()) {
			return new Result(false, "区块交易数量不正确");
		}
		
//		log.info("===============验证区块基本信息和签名耗时：{} ms", (System.currentTimeMillis() - now));
//		now = System.currentTimeMillis();
		
		//验证交易是否合法
		Coin coinbaseFee = Coin.ZERO; //coinbase 交易包含的金额，主要是手续费
		Coin fee = Coin.ZERO; 		  //手续费
		
		//每个区块只能包含一个coinbase交易，并且只能是第一个
		boolean coinbase = false;
		
		List<Transaction> txs = block.getTxs();
		for (Transaction tx : txs) {
			
			ValidatorResult<TransactionValidatorResult> rs = transactionValidator.valDo(tx, txs);
			
			if(!rs.getResult().isSuccess()) {
				throw new VerificationException(rs.getResult().getMessage());
			}
			//信用累积交易，比较特殊，这里单独验证
			if(tx.getType() == Definition.TYPE_CREDIT) {
				verifyCreditTransaction(tx, txs, block);
			}
			
			//区块的第一个交易必然是coinbase交易，除第一个之外的任何交易都不应是coinbase交易，否则出错
			if(!coinbase) {
				if(tx.getType() != Definition.TYPE_COINBASE) {
					throw new VerificationException("the block first tx is not coinbase tx");
				}
				coinbaseFee = Coin.valueOf(tx.getOutput(0).getValue());
				coinbase = true;
				continue;
			} else if(tx.getType() == Definition.TYPE_COINBASE) {
				throw new VerificationException("the block too much coinbase tx");
			}
			if(rs.getResult().getFee() != null) {
				fee = fee.add(rs.getResult().getFee());
			}
		}
		
//		log.info("===============验证交易耗时：{} ms", (System.currentTimeMillis() - now));
		now = System.currentTimeMillis();
		
		//验证本区块的双花
		List<ByteHash> outputIndexHashArray = new ArrayList<ByteHash>();
		for (Transaction t : txs) {
			List<TransactionInput> inputsTemp = t.getInputs();
			if(inputsTemp == null || inputsTemp.size() == 0) {
				continue;
			}
			for (TransactionInput in : t.getInputs()) {
				List<TransactionOutput> fromsTemp = in.getFroms();
				if(fromsTemp == null || fromsTemp.size() == 0) {
					continue;
				}
				for (TransactionOutput fromTemp : fromsTemp) {
					byte[] statusKey = fromTemp.getKey();
					
					ByteHash byteHash = new ByteHash(statusKey);
					if(outputIndexHashArray.contains(byteHash)) {
						log.warn("存在双花交易");
						return new Result(false, "存在双花交易");
					} else {
						outputIndexHashArray.add(byteHash);
					}
				}
			}
		}
		
//		log.info("===============验证双花耗时：{} ms", (System.currentTimeMillis() - now));
		
		//验证金额，coinbase交易的费用必须等于交易手续费
		//获取该高度的奖励
		Coin rewardCoin = ConsensusCalculationUtil.calculatReward(block.getHeight());
		if(!coinbaseFee.equals(fee.add(rewardCoin))) {
			log.warn("the fee error");
			return new Result(false, "交易金额错误");
		}
		//获取区块的最新高度
		BlockHeaderStore bestBlockHeader = blockStoreProvider.getBestBlockHeader();
		//必需衔接
		if(!block.getPreHash().equals(bestBlockHeader.getBlockHeader().getHash()) ||
				block.getHeight() != bestBlockHeader.getBlockHeader().getHeight() + 1) {
			log.warn("block info warn newblock {}, localblock {}", block.getHeight(), bestBlockHeader.getBlockHeader().getHeight());
			blockForkService.addBlockFork(block);
			return new Result(false, ERROR_CODE_HEIGHT_ERROR, "block info warn newblock {}, localblock {}");
		}
		
		return new Result(true);
	}
	
	/**
	 * 验证信用发放
	 */
	public void verifyCreditTransaction(Transaction tx, List<Transaction> txs, Block block) {
		if(!(tx instanceof CreditTransaction)) {
			throw new VerificationException("错误的交易");
		}
		//信用累计，信用惩罚在 ViolationTransaction 里面 
		CreditTransaction creditTx = (CreditTransaction) tx;
		if(creditTx.getReasonType() == Definition.CREDIT_TYPE_PAY) {
			//验证是否在系统设定的时间内只奖励过一次
			//要能快速的验证，需要良好的设计
			//最有效的方法是以空间换时间，把相关的信息存在到内存里面

			if(creditTx.getCredit() != Configure.CERT_CHANGE_PAY) {
				throw new VerificationException("信用值不正确");
			}
			
			//被奖励人
			byte[] hash160 = creditTx.getOwnerHash160();
			
			//验证凭证是否合法，凭证必须和信用在同一个块
			if(txs == null || creditTx.getReason() == null) {
				throw new VerificationException("凭证不存在");
			}
			Transaction certificateTx = null;
			for (Transaction txTemp : txs) {
				if(txTemp.getHash().equals(creditTx.getReason())) {
					certificateTx = txTemp;
					break;
				}
			}
			if(certificateTx == null) {
				throw new VerificationException("凭证没有找到");
			}
			
			if(certificateTx.getType() != Definition.TYPE_PAY) {
				throw new VerificationException("无效凭证");
			}
			
			//信用发放给正确的人
			byte[] hash160Temp = certificateTx.getInput(0).getFromScriptSig().getPubKeyHash();
			if(!Arrays.equals(hash160Temp, hash160)) {
				throw new VerificationException("信用没有发放给正确的人");
			}
			
			if(!creditCollectionService.verification(creditTx.getReasonType(), hash160, block.getTime())) {
				throw new VerificationException("验证失败，不能发放信用值");
			}
		} else {
			throw new VerificationException("暂时未实现的交易");
		}
	}
}
