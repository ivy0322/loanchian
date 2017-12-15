package org.loanchian.validator;

import org.loanchian.Configure;
import org.loanchian.account.Address;
import org.loanchian.consensus.ConsensusAccount;
import org.loanchian.consensus.ConsensusMeeting;
import org.loanchian.consensus.ConsensusPool;
import org.loanchian.core.*;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.kits.AccountKit;
import org.loanchian.mempool.MempoolContainer;
import org.loanchian.message.BlockHeader;
import org.loanchian.network.NetworkParams;
import org.loanchian.script.Script;
import org.loanchian.store.*;
import org.loanchian.transaction.Output;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.TransactionInput;
import org.loanchian.transaction.TransactionOutput;
import org.loanchian.transaction.business.*;
import org.loanchian.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * 交易验证器
 * @author ln
 *
 */
@Component
public class TransactionValidator {

	private final static Logger log = LoggerFactory.getLogger(org.loanchian.validator.TransactionValidator.class);

	@Autowired
	private NetworkParams network;
	@Autowired
	private ConsensusPool consensusPool;
	@Autowired
	private ConsensusMeeting consensusMeeting;
	@Autowired
	private BlockStoreProvider blockStoreProvider;
	@Autowired
	private ChainstateStoreProvider chainstateStoreProvider;
	@Autowired
	private AccountKit accountKit;
	@Autowired
	private DataSynchronizeHandler dataSynchronizeHandler;

	/**
	 * 交易验证器，验证交易的输入输出是否合法
	 * @param tx	待验证的交易
	 * @return ValidatorResult<TransactionValidatorResult>
	 */
	public ValidatorResult<TransactionValidatorResult> valDo(Transaction tx) {
		return valDo(tx, null);
	}

	/**
	 * 交易验证器，验证交易的输入输出是否合法
	 * @param tx	待验证的交易
	 * @param txs	当输入引用找不到时，就在这个列表里面查找（当同一个区块包含多个交易链时需要用到）
	 * @return ValidatorResult<TransactionValidatorResult>
	 */
	public ValidatorResult<TransactionValidatorResult> valDo(Transaction tx, List<Transaction> txs) {

		final TransactionValidatorResult result = new TransactionValidatorResult();
		ValidatorResult<TransactionValidatorResult> validatorResult = new ValidatorResult<TransactionValidatorResult>() {
			@Override
			public TransactionValidatorResult getResult() {
				return result;
			}
		};

		tx.verify();
		//验证交易的合法性
		if(tx instanceof BaseCommonlyTransaction) {
			((BaseCommonlyTransaction)tx).verifyScript();
		}

		//交易的txid不能和区块里面的交易重复
		TransactionStore verifyTX = blockStoreProvider.getTransaction(tx.getHash().getBytes());
		if(verifyTX != null) {

			result.setResult(false, TransactionValidatorResult.ERROR_CODE_EXIST, "交易hash与区块里的重复 " + tx.getHash());
			return validatorResult;
		}
		//如果是转帐交易
		//TODO 以下代码请使用状态模式重构
		if(tx.isPaymentTransaction() && tx.getType() != Definition.TYPE_COINBASE) {
			//验证交易的输入来源，是否已花费的交易，同时验证金额
			Coin txInputFee = Coin.ZERO;
			Coin txOutputFee = Coin.ZERO;

			//验证本次交易的输入
			List<TransactionInput> inputs = tx.getInputs();
			//交易引用的输入，赎回脚本必须一致
			byte[] scriptBytes = null;
			int i = 0;
			for (TransactionInput input : inputs) {
				scriptBytes = null;
				List<TransactionOutput> outputs = input.getFroms();
				if(outputs == null || outputs.size() == 0) {
					throw new VerificationException("交易没有引用输入");
				}
				for (TransactionOutput output : outputs) {
					//对上一交易的引用以及索引值
					Transaction fromTx = output.getParent();
					if(fromTx == null) {
						throw new VerificationException("交易没有正确的输入引用");
					}
					Sha256Hash fromId = fromTx.getHash();
					int index = output.getIndex();

					//如果引用已经是完整的交易，则不查询
					if(fromTx.getOutputs() == null || fromTx.getOutputs().isEmpty()) {
						//需要设置引用的完整交易
						//查询内存池里是否有该交易
						Transaction preTransaction = MempoolContainer.getInstace().get(fromId);
						//内存池里面没有，那么是否在传入的列表里面
						if(preTransaction == null && txs != null && txs.size() > 0) {
							for (Transaction transaction : txs) {
								if(transaction.getHash().equals(fromId)) {
									preTransaction = transaction;
									break;
								}
							}
						}
						if(preTransaction == null) {
							//内存池和传入的列表都没有，那么去存储里面找
							TransactionStore preTransactionStore = blockStoreProvider.getTransaction(fromId.getBytes());
							if(preTransactionStore == null) {
								result.setResult(false, TransactionValidatorResult.ERROR_CODE_NOT_FOUND, "引用了不存在的交易");
								return validatorResult;
							}
							preTransaction = preTransactionStore.getTransaction();
						}
						output.setParent(preTransaction);
						output.setScript(preTransaction.getOutput(index).getScript());
						fromTx = preTransaction;
					}

					//验证引用的交易是否可用
					if(fromTx.getLockTime() < 0l ||
							(fromTx.getLockTime() > Definition.LOCKTIME_THRESHOLD && fromTx.getLockTime() > TimeService.currentTimeSeconds())
							|| (fromTx.getLockTime() < Definition.LOCKTIME_THRESHOLD && fromTx.getLockTime() > network.getBestHeight())) {
						throw new VerificationException("引用了不可用的交易");
					}
					//验证引用的交易输出是否可用
					long lockTime = output.getLockTime();
					if(lockTime < 0l || (lockTime > Definition.LOCKTIME_THRESHOLD && lockTime > TimeService.currentTimeSeconds())
							|| (lockTime < Definition.LOCKTIME_THRESHOLD && lockTime > network.getBestHeight())) {
						throw new VerificationException("引用了不可用的交易输出");
					}

					TransactionOutput preOutput = fromTx.getOutput(index);
					txInputFee = txInputFee.add(Coin.valueOf(preOutput.getValue()));
					output.setValue(preOutput.getValue());
					//验证交易赎回脚本必须一致
					if(scriptBytes == null) {
						scriptBytes = preOutput.getScriptBytes();
					} else if(!Arrays.equals(scriptBytes, preOutput.getScriptBytes())) {
						throw new VerificationException("错误的输入格式，不同的交易赎回脚本不能合并");
					}

					//验证交易不能双花
					byte[] statusKey = output.getKey();
					byte[] state = chainstateStoreProvider.getBytes(statusKey);
					if((state == null || Arrays.equals(state, new byte[]{ 1 })) && txs != null && !txs.isEmpty()) {

					} else if(Arrays.equals(state, new byte[]{2})) {
						//已经花费了
						result.setResult(false, TransactionValidatorResult.ERROR_CODE_USED, "引用了已花费的交易");
						return validatorResult;
					}
				}
				Script verifyScript = new Script(scriptBytes);
				if(verifyScript.isConsensusOutputScript()) {
					//共识保证金引用脚本，则验证
					//因为共识保证金，除了本人会操作，还会有其它共识人操作
					//并且不一定是转到自己的账户，所以必须对输入输出都做严格的规范
					if(!(tx.getType() == Definition.TYPE_REM_CONSENSUS || tx.getType() == Definition.TYPE_VIOLATION)) {
						throw new VerificationException("不合法的交易引用");
					}
					//输入必须只有一个
					if(inputs.size() != 1 || inputs.get(0).getFroms().size() != 1) {
						result.setResult(false, "该笔交易有保证金的引用，输入个数不对");
						return validatorResult;
					}
					//输出必须只有一个，切必须按照指定的类型输出到相应的账户
					if(tx.getOutputs().size() != 1) {
						result.setResult(false, "该笔交易有保证金的引用，输出个数不对");
						return validatorResult;
					}
					TransactionOutput ouput = tx.getOutputs().get(0);
					//验证保证金的数量
					if(ouput.getValue() != inputs.get(0).getFroms().get(0).getValue()) {
						result.setResult(false, "保证金的输入输出金额不匹配");
						return validatorResult;
					}
					Script outputScript = ouput.getScript();
					//必须输出到地址
					if(!outputScript.isSentToAddress()) {
						result.setResult(false, "保证金的输出不正确");
						return validatorResult;
					}
					//必须输出到指定的账户
					//自己的账户
					byte[] selfAccount = verifyScript.getChunks().get(0).data;
					//惩罚保证金接收账户
					byte[] punishmentAccount = verifyScript.getChunks().get(1).data;
					//输出账户
					byte[] ouputAccount = outputScript.getChunks().get(2).data;
					if(tx.getType() == Definition.TYPE_REM_CONSENSUS && !Arrays.equals(selfAccount, ouputAccount)) {
						result.setResult(false, "保证金的输出不合法,应该是保证金所属者");
						return validatorResult;
					} else if(tx.getType() == Definition.TYPE_VIOLATION) {
						//违规处理
						ViolationTransaction vt = (ViolationTransaction) tx;
						//证据
						ViolationEvidence violationEvidence = vt.getViolationEvidence();

						if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK && !Arrays.equals(selfAccount, ouputAccount)) {
							result.setResult(false, "超时不出块,保证金的输出不合法,应该是保证金所属者");
							return validatorResult;
						} else if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_REPEAT_BROADCAST_BLOCK && !Arrays.equals(punishmentAccount, ouputAccount)) {
							result.setResult(false, "严重违规,重复出块,保证金的输出不合法,应该是罚没接收账户");
							return validatorResult;
						}
					}
				} else {
					//验证赎回脚本
					if(!(
						tx.getHash().toString().equals("eef6ef8421229850dfc7e276264b179eced6699f518691c555652df73a5cf86a")
								|| tx.getHash().toString().equals("f134df4fdf57228cf95b8d69f038b872d04729868010dae62a101b0c7fd1aa91")
					)) {
						input.getScriptSig().run(tx, i, verifyScript);
					}
				}
				i ++;
			}
			//验证本次交易的输出
			List<TransactionOutput> outputs = tx.getOutputs();
			for (Output output : outputs) {
				Coin outputCoin = Coin.valueOf(output.getValue());
				//输出金额不能为负数
				if(outputCoin.isLessThan(Coin.ZERO)) {
					result.setResult(false, "输出金额不能为负数");
					return validatorResult;
				}
				if(outputCoin.isGreaterThan(Configure.MAX_OUTPUT_COIN)) {
					result.setResult(false, "输出金额不能超过1亿");
					return validatorResult;
				}
				txOutputFee = txOutputFee.add(outputCoin);
			}
			//验证不能给自己转账
			boolean isLock = false;
			if(tx.getType() == Definition.TYPE_PAY) {
				Script inputScript = new Script(scriptBytes);
				byte[] sender = inputScript.getChunks().get(2).data;
				TransactionOutput output = outputs.get(0);
				byte[] receiver = output.getScript().getChunks().get(2).data;
				if(Arrays.equals(sender, receiver)) {
					//不能给自己转账，因为毫无意义，一种情况除外
					//锁仓的时候，除外，但是锁仓需要大于24小时，并金额大于100
					Coin value = Coin.valueOf(output.getValue());
					long lockTime = output.getLockTime();

					//发送的金额必须大于100
					if(value.compareTo(Coin.COIN.multiply(100)) < 0) {
						result.setResult(false, "锁仓的金额需达到100");
						return validatorResult;
					}
					//锁仓的时间必须大于24小时
					if(lockTime - tx.getTime() < 24 * 60 * 60) {
						result.setResult(false, "锁仓时间必须大于24小时");
						return validatorResult;
					}
					isLock = true;
				}
			}

			//输出金额不能大于输入金额
			if(txOutputFee.isGreaterThan(txInputFee)) {
				result.setResult(false, "输出金额不能大于输入金额");
				return validatorResult;
			} else {
				result.setFee(txInputFee.subtract(txOutputFee));
			}
			if(tx.getType() == Definition.TYPE_PAY && network.getBestBlockHeight() > 0 && !isLock) {
				if(result.getFee().compareTo(Definition.MIN_PAY_FEE) < 0) {
					result.setResult(false, "手续费至少为0.1个INS");
					return validatorResult;
				}
			}

			if(tx.getType() == Definition.TYPE_REG_CONSENSUS) {
				//申请成为共识节点
				RegConsensusTransaction regConsensusTx = (RegConsensusTransaction) tx;
				byte[] hash160 = regConsensusTx.getHash160();
				//获取申请人信息，包括信用和可用余额
				AccountStore accountStore = chainstateStoreProvider.getAccountInfo(hash160);
				if(accountStore == null && regConsensusTx.isCertAccount()) {
					result.setResult(false, "账户不存在");
					return validatorResult;
				}

				//判断是否达到共识条件
				long credit = (accountStore == null ? 0 : accountStore.getCert());
				BlockHeader blockHeader = blockStoreProvider.getBlockHeaderByperiodStartTime(regConsensusTx.getPeriodStartTime());
				long consensusCredit = ConsensusCalculationUtil.getConsensusCredit(blockHeader.getHeight());
				if(credit < consensusCredit) {
					//信用不够
					result.setResult(false, "共识账户信用值过低 " + credit + "  " + consensusCredit);
					return validatorResult;
				}

				//判断是否已经是共识节点
				if(consensusPool.contains(hash160)) {
					//已经是共识节点了
					result.setResult(false, "已经是共识节点了,勿重复申请");
					return validatorResult;
				}
				//验证时段
				long periodStartTime = regConsensusTx.getPeriodStartTime();
				//必须是最近的几轮里
				if(dataSynchronizeHandler.hasComplete() && consensusMeeting.getMeetingItem(periodStartTime) == null) {
					throw new VerificationException("申请时段不合法");
				}
				//验证保证金
				//当前共识人数
				int currentConsensusSize = consensusMeeting.analysisConsensusSnapshots(periodStartTime).size();
				//共识保证金
//				Coin recognizance = ConsensusCalculationUtil.calculatRecognizance(currentConsensusSize, blockHeader.getHeight());
//				if(!Coin.valueOf(outputs.get(0).getValue()).equals(recognizance)) {
//					result.setResult(false, "保证金不正确");
//					currentConsensusSize = consensusMeeting.analysisConsensusSnapshots(periodStartTime).size();
//					return validatorResult;
//				}
			} else if(tx.getType() == Definition.TYPE_REM_CONSENSUS) {
				//退出共识交易
				RemConsensusTransaction remConsensusTx = (RemConsensusTransaction) tx;
				byte[] hash160 = remConsensusTx.getHash160();
				//判断是否已经是共识节点
				if(!consensusPool.contains(hash160)) {
					//不是共识节点，该交易不合法
					result.setResult(false, "不是共识节点了，该交易不合法");
					return validatorResult;
				}
			} else if(tx instanceof ViolationTransaction) {
				//违规处罚交易，验证违规证据是否合法
				ViolationTransaction vtx = (ViolationTransaction)tx;

				//违规证据
				ViolationEvidence violationEvidence = vtx.getViolationEvidence();
				if(violationEvidence == null) {
					result.setResult(false, "处罚交易违规证据不能为空");
					return validatorResult;
				}
				//违规证据是否已经被处理
				Sha256Hash evidenceHash = violationEvidence.getEvidenceHash();
				byte[] ptxHashBytes = chainstateStoreProvider.getBytes(evidenceHash.getBytes());
				if(ptxHashBytes != null) {
					result.setResult(false, "该违规已经被处理，不需要重复处理");
					return validatorResult;
				}

				//验证证据合法性
				if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK) {
					//超时未出块处罚
					NotBroadcastBlockViolationEvidence notBroadcastBlock = (NotBroadcastBlockViolationEvidence) violationEvidence;
					//验证逻辑
					byte[] hash160 = notBroadcastBlock.getAudienceHash160();
					long currentPeriodStartTime = notBroadcastBlock.getCurrentPeriodStartTime();
					long previousPeriodStartTime = notBroadcastBlock.getPreviousPeriodStartTime();

					BlockHeader startBlockHeader = blockStoreProvider.getBestBlockHeader().getBlockHeader();
					//取得当前轮的最后一个块
					while(true) {
						BlockHeaderStore lastHeaderStore = blockStoreProvider.getHeader(startBlockHeader.getPreHash().getBytes());
						if(lastHeaderStore != null) {
							BlockHeader lastHeader = lastHeaderStore.getBlockHeader();
							if(lastHeader.getPeriodStartTime() >= currentPeriodStartTime && !Sha256Hash.ZERO_HASH.equals(lastHeader.getPreHash())) {
								startBlockHeader = lastHeader;
							} else {
								startBlockHeader = lastHeader;
								break;
							}
						}
					}

					//原本应该打包的上一个块
					if(startBlockHeader == null || (!Sha256Hash.ZERO_HASH.equals(startBlockHeader.getPreHash()) && startBlockHeader.getPeriodStartTime() != previousPeriodStartTime)) {
						result.setResult(false, "违规证据中的两轮次不相连");
						return validatorResult;
					}

					//验证该轮的时段
					int index = getConsensusPeriod(hash160, currentPeriodStartTime);
					if(index == -1) {
						result.setResult(false, "证据不成立，该人不在本轮共识列表中");
						return validatorResult;
					}
					BlockHeaderStore currentStartBlockHeaderStore = blockStoreProvider.getHeaderByHeight(startBlockHeader.getHeight() + 1);
					if(currentStartBlockHeaderStore == null) {
						result.setResult(false, "证据不成立，当前轮还没有打包数据");
						return validatorResult;
					}
					BlockHeader currentStartBlockHeader = currentStartBlockHeaderStore.getBlockHeader();
					while(true) {
						if(currentStartBlockHeader.getTimePeriod() == index) {
							result.setResult(false, "证据不成立,本轮有出块");
							return validatorResult;
						}
						if(currentStartBlockHeader.getTimePeriod() < index) {
							BlockHeaderStore preBlockHeaderStoreTemp = blockStoreProvider.getHeaderByHeight(currentStartBlockHeader.getHeight() + 1);

							if(preBlockHeaderStoreTemp == null || preBlockHeaderStoreTemp.getBlockHeader() == null
									|| preBlockHeaderStoreTemp.getBlockHeader().getPeriodStartTime() != currentPeriodStartTime) {
								break;
							}

							currentStartBlockHeader = preBlockHeaderStoreTemp.getBlockHeader();
						} else {
							break;
						}
					}
					//验证上一轮的时段
					index = getConsensusPeriod(hash160, previousPeriodStartTime);
					if(index == -1) {
						result.setResult(false, "证据不成立，该人不在上一轮共识列表中");
						return validatorResult;
					}
					while(true) {
						if(startBlockHeader.getTimePeriod() == index) {
							result.setResult(false, "证据不成立,上一轮有出块");
							return validatorResult;
						}
						if(startBlockHeader.getTimePeriod() < index) {
							BlockHeaderStore preBlockHeaderStoreTemp = blockStoreProvider.getHeader(startBlockHeader.getPreHash().getBytes());

							if(preBlockHeaderStoreTemp == null || preBlockHeaderStoreTemp.getBlockHeader() == null
									|| preBlockHeaderStoreTemp.getBlockHeader().getPeriodStartTime() != previousPeriodStartTime) {
								break;
							}

							startBlockHeader = preBlockHeaderStoreTemp.getBlockHeader();
						} else {
							break;
						}
					}
				} else if(violationEvidence.getViolationType() == ViolationEvidence.VIOLATION_TYPE_REPEAT_BROADCAST_BLOCK) {
					//重复出块的验证
					//验证证据的合法性
					//违规证据
					RepeatBlockViolationEvidence repeatBlockViolationEvidence = (RepeatBlockViolationEvidence) violationEvidence;

					List<BlockHeader> blockHeaders = repeatBlockViolationEvidence.getBlockHeaders();

					//证据不能为空，且必须是2条记录
					if(blockHeaders == null || blockHeaders.size() != 2) {
						result.setResult(false, "证据个数不正确");
						return validatorResult;
					}

					BlockHeader blockHeader1 = blockHeaders.get(0);
					BlockHeader blockHeader2 = blockHeaders.get(1);
					if(!Arrays.equals(blockHeader1.getHash160(), blockHeader2.getHash160()) ||
							!Arrays.equals(blockHeader1.getHash160(), repeatBlockViolationEvidence.getAudienceHash160())) {
						result.setResult(false, "违规证据里的两个块打包人不相同,或者证据与被处理人不同");
						return validatorResult;
					}
					if(blockHeader1.getPeriodStartTime() != blockHeader2.getPeriodStartTime()) {
						result.setResult(false, "违规证据里的两个块时段不相同");
						return validatorResult;
					}
					//验证签名
					try {
						blockHeader1.verifyScript();
						blockHeader2.verifyScript();
					} catch (Exception e) {
						result.setResult(false, "违规证据里的两个块验证签名不通过");
						return validatorResult;
					}
				}
			}

		} else if(tx.getType() == Definition.TYPE_CERT_ACCOUNT_REGISTER) {
			//帐户注册
			CertAccountRegisterTransaction regTx = (CertAccountRegisterTransaction) tx;
			//注册的hash160地址，不能与现有的地址重复，当然正常情况重复的机率为0，不排除有人恶意广播数据
			byte[] hash160 = regTx.getHash160();

			byte[] txid = chainstateStoreProvider.getBytes(hash160);
			if(txid != null) {
				result.setResult(false, "注册的账户重复");
				return validatorResult;
			}

			if(chainstateStoreProvider.isCertAccountRevoked(regTx.getSuperhash160())){
				result.setResult(false, "新增该账户的上级账户已经被吊销");
				return validatorResult;
			}

			if(regTx.getLevel()>Configure.MAX_CERT_LEVEL){
				result.setResult(false, "新增该账户的上级账户不具备该权限");
				return validatorResult;
			}

			//验证账户注册，必须是超级账号签名的才能注册
			byte[] verTxid = regTx.getScript().getChunks().get(1).data;
			byte[] verTxBytes = chainstateStoreProvider.getBytes(verTxid);
			if(verTxBytes == null) {
				result.setResult(false, "签名错误：verTxid="+Sha256Hash.wrap(verTxid));
				return validatorResult;
			}
			CertAccountRegisterTransaction verTx = new CertAccountRegisterTransaction(network, verTxBytes);

		} else if(tx.getType() == Definition.TYPE_CERT_ACCOUNT_UPDATE) {
			//认证账户修改信息
			CertAccountUpdateTransaction updateTx = (CertAccountUpdateTransaction) tx;
			byte[] hash160 = updateTx.getHash160();

			//必须是自己最新的账户状态
			byte[] verTxid = updateTx.getScript().getChunks().get(1).data;
			byte[] verTxBytes = chainstateStoreProvider.getBytes(verTxid);
			if(verTxBytes == null) {
				result.setResult(false, "签名错误：verTxid="+Sha256Hash.wrap(verTxid));
				return validatorResult;
			}
			//检查用户是否为认证账户，检查用户状态是否可用
			AccountStore accountInfo = chainstateStoreProvider.getAccountInfo(hash160);
			if(accountInfo == null || accountInfo.getType() != network.getCertAccountVersion() || accountInfo.getStatus() !=0 ) {
				result.setResult(false, "只有激活状态下的认证账户才能修改");
				return validatorResult;
			}


			CertAccountRegisterTransaction verTx = new CertAccountRegisterTransaction(network, verTxBytes);

			//认证帐户，就需要判断是否经过认证的
			if(!Arrays.equals(verTx.getHash160(), hash160)) {
				result.setResult(false, "错误的签名，账户不匹配");
				return validatorResult;
			}
		}else if(tx.getType() == Definition.TYPE_CERT_ACCOUNT_REVOKE){
			CertAccountRevokeTransaction revokeTx = (CertAccountRevokeTransaction) tx;
			byte[] hash160 = revokeTx.getHash160();
			byte[] revokehash160 = revokeTx.getRevokeHash160();


			//检查用户是否为认证账户，检查用户状态是否可用
			AccountStore accountInfo = chainstateStoreProvider.getAccountInfo(hash160);
			AccountStore raccountinfo  = chainstateStoreProvider.getAccountInfo(revokehash160);
			if(accountInfo.getLevel() >= Configure.MAX_CERT_LEVEL){
				result.setResult(false, "签发该账户的上级账户不具备该权限");
				return validatorResult;
			}


			if(accountInfo == null || accountInfo.getType() != network.getCertAccountVersion() || accountInfo.getStatus() !=0 ) {
				result.setResult(false, "只有激活状态下的认证账户才能修改");
				return validatorResult;
			}
			if(raccountinfo == null){
				result.setResult(false, "被吊销的账户不存在");
				return validatorResult;
			}
			//检查账户是否被吊销
			if(chainstateStoreProvider.isCertAccountRevoked(hash160)){
				result.setResult(false, "本地管理员账户已经被吊销");
				return validatorResult;
			}
			if(chainstateStoreProvider.isCertAccountRevoked(revokehash160)){
				result.setResult(false, "将要吊销的账户已经被吊销");
				return validatorResult;
			}

			if((accountInfo.getLevel() == 3 && !Arrays.equals(raccountinfo.getSupervisor(),accountInfo.getHash160())) || accountInfo.getLevel()>3|| accountInfo.getLevel()>= raccountinfo.getLevel()){
				result.setResult(false, "不具备吊销该账户的权限");
				return validatorResult;
			}


		}
		else if(tx.getType() == Definition.TYPE_REG_ALIAS) {
			//注册别名
			RegAliasTransaction rtx = (RegAliasTransaction) tx;
			//账户必须达到规定的信用，才能注册别名
			AccountStore accountInfo = chainstateStoreProvider.getAccountInfo(rtx.getHash160());
			if(accountInfo == null || accountInfo.getCert() < Configure.REG_ALIAS_CREDIT) {
				result.setResult(false, "账户信用达到" + Configure.REG_ALIAS_CREDIT + "之后才能注册别名");
				return validatorResult;
			}
			//是否已经设置过别名了
			byte[] alias = accountInfo.getAlias();
			if(alias != null && alias.length > 0) {
				result.setResult(false, "已经设置别名，不能重复设置");
				return validatorResult;
			}
			//别名是否已经存在
			accountInfo = chainstateStoreProvider.getAccountInfoByAlias(alias);
			if(accountInfo != null) {
				result.setResult(false, "别名已经存在");
				return validatorResult;
			}
		} else if(tx.getType() == Definition.TYPE_UPDATE_ALIAS) {
			//修改别名
			UpdateAliasTransaction utx = (UpdateAliasTransaction) tx;
			//账户必须达到规定的信用，才能修改别名
			AccountStore accountInfo = chainstateStoreProvider.getAccountInfo(utx.getHash160());
			if(accountInfo == null || accountInfo.getCert() < Configure.UPDATE_ALIAS_CREDIT) {
				result.setResult(false, "账户信用达到" + Configure.UPDATE_ALIAS_CREDIT + "之后才能修改别名");
				return validatorResult;
			}
			//是否已经设置过别名了
			byte[] alias = accountInfo.getAlias();
			if(alias == null || alias.length == 0) {
				result.setResult(false, "没有设置别名，不能修改");
				return validatorResult;
			}
			//新别名是否已经存在
			accountInfo = chainstateStoreProvider.getAccountInfoByAlias(utx.getAlias());
			if(accountInfo != null) {
				result.setResult(false, "新别名已经存在");
				return validatorResult;
			}
		}

		result.setSuccess(true);
		result.setMessage("ok");
		return validatorResult;
	}

	/**
	 * 获取某个账号在某轮共识中的时段
	 * 如果没有找到则返回-1
	 * @param hash160
	 * @param periodStartTime
	 * @return int
	 */
	public int getConsensusPeriod(byte[] hash160, long periodStartTime) {
		List<ConsensusAccount> consensusList = consensusMeeting.analysisConsensusSnapshots(periodStartTime);
//		log.info("被处理人： {} , 开始时间： {} ,  列表： {}", new Address(network, hash160).getBase58(), DateUtil.convertDate(new Date(periodStartTime*1000)), consensusList);
		if(log.isDebugEnabled()) {
			log.debug("被处理人： {} , 开始时间： {} ,  列表： {}", new Address(network, hash160).getBase58(), DateUtil.convertDate(new Date(periodStartTime*1000)), consensusList);
		}
		//获取位置
		for (int i = 0; i < consensusList.size(); i++) {
			ConsensusAccount consensusAccount = consensusList.get(i);
			if(Arrays.equals(hash160, consensusAccount.getHash160())) {
				return i;
			}
		}
		return -1;
	}
}
