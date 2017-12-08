package org.loanchian.wallet.controllers;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.text.Font;
import javafx.util.Callback;
import org.loanchian.Configure;
import org.loanchian.account.Account;
import org.loanchian.account.Address;
import org.loanchian.core.*;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.mempool.MempoolContainer;
import org.loanchian.network.NetworkParams;
import org.loanchian.script.Script;
import org.loanchian.store.AccountStore;
import org.loanchian.store.TransactionStore;
import org.loanchian.transaction.Output;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.TransactionInput;
import org.loanchian.transaction.TransactionOutput;
import org.loanchian.transaction.business.*;
import org.loanchian.utils.*;
import org.loanchian.wallet.Constant;
import org.loanchian.wallet.entity.DetailValue;
import org.loanchian.wallet.entity.DetailValueCell;
import org.loanchian.wallet.entity.HashValueCell;
import org.loanchian.wallet.entity.TransactionEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * 交易记录页面控制器
 * @author ln
 *
 */
public class TransactionRecordController implements SubPageController {
	
	private static final Logger log = LoggerFactory.getLogger(TransactionRecordController.class);
	
	public TableView<TransactionEntity> table;
	public TableColumn<TransactionEntity, Long> status;
	public TableColumn<TransactionEntity, DetailValue> hash;
	public TableColumn<TransactionEntity, String> type;
	public TableColumn<TransactionEntity, DetailValue> detail;
	public TableColumn<TransactionEntity, String> amount;
	public TableColumn<TransactionEntity, String> time;
	
	/**
	 *  FXMLLoader 调用的初始化
	 */
    public void initialize() {
    	status.setCellValueFactory(new PropertyValueFactory<TransactionEntity, Long>("status"));
    	status.setCellFactory(new Callback<TableColumn<TransactionEntity,Long>, TableCell<TransactionEntity,Long>>() {
			public TableCell<TransactionEntity, Long> call(TableColumn<TransactionEntity, Long> param) {
				return new TableCell<TransactionEntity, Long>(){
					
					protected void updateItem(Long item, boolean empty) {
						super.updateItem(item, empty);
						Label status_icon = new Label();
						Image icon;
						Tooltip tip = new Tooltip();
					
						if (item == null || empty) {
							setGraphic(null);
							return ;
						} 
						if (item.longValue() >= Constant.CONFIRM_NUMBER) {
							icon = new Image("/images/confirmed.png");
							tip = new Tooltip("已确认交易\n"+"确认数为"+item);
						} else {
							icon = new Image("/images/unconfirmed.png");
							tip = new Tooltip("交易待确认\n"+"经过"+ item +"次确认");
						}
						tip.setFont(Font.font(14));
						tip.setWrapText(true);
						status_icon = new Label(null, new ImageView(icon));
						status_icon.setTooltip(tip);
						setGraphic(status_icon);
					}
				};
			}
		});
		hash.setCellValueFactory(new PropertyValueFactory<TransactionEntity, DetailValue>("hash"));
		hash.setCellFactory(new Callback<TableColumn<TransactionEntity, DetailValue>, TableCell<TransactionEntity, DetailValue>>() {
			@Override public TableCell<TransactionEntity, DetailValue> call(TableColumn<TransactionEntity, DetailValue> tableColumn) {
				return new HashValueCell();
			}
		});
    	type.setCellValueFactory(new PropertyValueFactory<TransactionEntity, String>("type"));

    	detail.setCellValueFactory(new PropertyValueFactory<TransactionEntity, DetailValue>("detail"));
    	detail.setCellFactory(new Callback<TableColumn<TransactionEntity, DetailValue>, TableCell<TransactionEntity, DetailValue>>() {
	    	@Override public TableCell<TransactionEntity, DetailValue> call(TableColumn<TransactionEntity, DetailValue> tableColumn) {
	    		return new DetailValueCell();
	    	}
	    });
    	amount.setCellValueFactory(new PropertyValueFactory<TransactionEntity, String>("amount"));
    	time.setCellValueFactory(new PropertyValueFactory<TransactionEntity, String>("time"));
    }
    
    /**
     * 初始化
     */
    public void initDatas() {
    	if(log.isDebugEnabled()) {
    		log.debug("加载交易数据···");
    	}
    	
    	List<TransactionStore> txs = LoanchainInstance.getInstance().getAccountKit().getTransactions();

    	
    	List<TransactionEntity> list = new ArrayList<TransactionEntity>();
    	
    	tx2Entity(txs, list);
    	
    	ObservableList<TransactionEntity> datas = FXCollections.observableArrayList(list);
    	datas.sort(new Comparator<TransactionEntity>() {
			@Override
			public int compare(TransactionEntity o1, TransactionEntity o2) {
				if(o1.getTime() == null || o2.getTime() == null || o2.getTime().equals(o1.getTime())) {
					return o2.getTxHash().compareTo(o1.getTxHash());
				} else {
					return o2.getTime().compareTo(o1.getTime());
				}
			}
		});
    	
    	table.setItems(datas);
    }

	private void tx2Entity(List<TransactionStore> txsList, List<TransactionEntity> list) {
		if(txsList != null && txsList.size() > 0) {
			//翻转数组
			Collections.reverse(txsList);
			
			//当前最新区块高度
			NetworkParams network = LoanchainInstance.getInstance().getAppKit().getNetwork();
			long bestBlockHeight = network.getBestBlockHeight();
			
			AccountKit accountKit = LoanchainInstance.getInstance().getAccountKit();
			
			List<Account> accounts = LoanchainInstance.getInstance().getAccountKit().getAccountList();
			
			for (TransactionStore txs : txsList) {
				
				//是否是转出
				boolean isSendout = false;
				
				Transaction tx = txs.getTransaction();
				
				String type = null, detail = "", amount = null, time = null;
				DetailValue detailValue = new DetailValue();
				
				if(tx.getType() == Definition.TYPE_COINBASE ||
						tx.getType() == Definition.TYPE_PAY) {
					
					if(tx.getType() == Definition.TYPE_COINBASE) {
						type = "共识奖励";
					} else {
						type = "现金交易";
					}
					
					String inputAddress = null;
					String outputAddress = null;
					
					List<TransactionInput> inputs = tx.getInputs();
					if(tx.getType() != Definition.TYPE_COINBASE && inputs != null && inputs.size() > 0) {
						for (TransactionInput input : inputs) {
							if(input.getFroms() == null || input.getFroms().size() == 0) {
								continue;
							}
							for (TransactionOutput from : input.getFroms()) {
								TransactionStore fromTx = LoanchainInstance.getInstance().getAccountKit().getTransaction(from.getParent().getHash());
								
								Transaction ftx = null;
								if(fromTx == null) {
									//交易不存在区块里，那么应该在内存里面
									ftx = MempoolContainer.getInstace().get(from.getParent().getHash());
								} else {
									ftx = fromTx.getTransaction();
								}
								if(ftx == null) {
									continue;
								}
								Output fromOutput = ftx.getOutput(from.getIndex());
								
								Script script = fromOutput.getScript();
								for (Account account : accounts) {
									if(script.isSentToAddress() && Arrays.equals(script.getChunks().get(2).data, account.getAddress().getHash160())) {
										isSendout = true;
										break;
									}
								}
								
								if(script.isSentToAddress()) {
									inputAddress = new Address(network, script.getAccountType(network), script.getChunks().get(2).data).getBase58();
									
//								detail += "\r\n" + new Address(network, script.getAccountType(network), script.getChunks().get(2).data).getBase58()+"(-"+Coin.valueOf(fromOutput.getValue()).toText()+")";
								}
							}
						}
					}
					
					List<TransactionOutput> outputs = tx.getOutputs();
					
					for (TransactionOutput output : outputs) {
						Script script = output.getScript();
						if(script.isSentToAddress()) {
							if(StringUtil.isEmpty(outputAddress)) {
								outputAddress = new Address(network, script.getAccountType(network), script.getChunks().get(2).data).getBase58();
							}
							
//							detail += "\r\n" + new Address(network, script.getAccountType(network), script.getChunks().get(2).data).getBase58()+"(+"+Coin.valueOf(output.getValue()).toText()+")";
							if(tx.getLockTime() < 0 || output.getLockTime() < 0) {
								detail += "(永久锁定)";
							} else if(((tx.getLockTime() > Definition.LOCKTIME_THRESHOLD && tx.getLockTime() > TimeService.currentTimeSeconds()) ||
									(tx.getLockTime() < Definition.LOCKTIME_THRESHOLD && tx.getLockTime() > bestBlockHeight)) ||
									((output.getLockTime() > Definition.LOCKTIME_THRESHOLD && output.getLockTime() > TimeService.currentTimeSeconds()) ||
											(output.getLockTime() < Definition.LOCKTIME_THRESHOLD && output.getLockTime() > bestBlockHeight))) {
								long lockTime;
								if(tx.getLockTime() > output.getLockTime()) {
									lockTime = tx.getLockTime();
								} else {
									lockTime = output.getLockTime();
								}
								if(lockTime > Definition.LOCKTIME_THRESHOLD) {
									detail += "("+ DateUtil.convertDate(new Date(lockTime * 1000))+"后可用)";
								} else {
									detail += "(区块高度达到"+lockTime+"时可用)";
								}
							}
						}
					}
					
					if(isSendout) {
						//是否是锁仓交易
						if(inputAddress.equals(outputAddress)) {
							type = "锁仓交易";
							detail = outputAddress+" \n" + detail;
						} else {
							detail = "转给 " + outputAddress + "";
						}
					} else {
						//接收，判断是否是共识奖励
						if(tx.getType() != Definition.TYPE_COINBASE) {
							if(inputAddress==null)
							{
								inputAddress ="未确认交易退款";
							}
							detail = "来自 "+inputAddress + (StringUtil.isEmpty(detail)?"":("\n"+detail));
						} else {
							detail = outputAddress+" (+"+ Coin.valueOf(outputs.get(0).getValue()).toText()+")\n" + detail;
						}
					}
					if(tx.getRemark() != null && tx.getRemark().length > 0) {
						try {
							detail += "\n(留言：" + new String(tx.getRemark(), "utf-8") + ")";
						} catch (UnsupportedEncodingException e) {
						}
					}
				} else if(tx.getType() == Definition.TYPE_CERT_ACCOUNT_REGISTER ||
						tx.getType() == Definition.TYPE_CERT_ACCOUNT_UPDATE) {
					//认证账户注册
					CertAccountRegisterTransaction crt = (CertAccountRegisterTransaction) tx;
					type = tx.getType() == Definition.TYPE_CERT_ACCOUNT_REGISTER ? "账户注册" : "修改信息";
					
					List<AccountKeyValue> bodyContents = crt.getBody().getContents();
					if(bodyContents!=null && bodyContents.size()>0){
						for (AccountKeyValue keyValuePair : bodyContents) {
							if(AccountKeyValue.LOGO.getCode().equals(keyValuePair.getCode())) {
								//图标
								detailValue.setImg(keyValuePair.getValue());
							} else {
								if(!"".equals(detail)) {
									detail += "\r\n";
								}
								detail += keyValuePair.getName()+" : " + keyValuePair.getValueToString();
							}
						}
					}
				} else if(tx.getType() == Definition.TYPE_REG_CONSENSUS ||
						tx.getType() == Definition.TYPE_REM_CONSENSUS) {
					if(tx.getType() == Definition.TYPE_REG_CONSENSUS) {
						detail = "提交保证金";
						type = "注册共识";
						isSendout = true;
					} else {
						detail = "赎回保证金";
						type = "退出共识";
						isSendout = false;
					}
				} else if(tx.getType() == Definition.TYPE_CREDIT) {
					CreditTransaction ctx = (CreditTransaction) tx;
					
					type = "增加信用";
					
					String reason = "初始化";
					if(ctx.getReasonType() == Definition.CREDIT_TYPE_PAY) {
						reason = String.format("%s小时内第一笔转账", Configure.CERT_CHANGE_PAY_INTERVAL/3600000l);
					}
					detail += "信用 +" + ctx.getCredit() + " 原因：" + reason;
				} else if(tx.getType() == Definition.TYPE_VIOLATION) {
					ViolationTransaction vtx = (ViolationTransaction) tx;
					
					type = "违规处罚";
					
					ViolationEvidence evidence = vtx.getViolationEvidence();
					int violationType = evidence.getViolationType();
					String reason = "";
					long credit = 0;
					if(violationType == ViolationEvidence.VIOLATION_TYPE_NOT_BROADCAST_BLOCK) {
						NotBroadcastBlockViolationEvidence nbve = (NotBroadcastBlockViolationEvidence) evidence;
						reason = String.format("共识过程中，开始时间为%s的轮次超时未出块", DateUtil.convertDate(new Date(nbve.getCurrentPeriodStartTime() * 1000)));
						credit = Configure.CERT_CHANGE_TIME_OUT;
					} else if(violationType == ViolationEvidence.VIOLATION_TYPE_REPEAT_BROADCAST_BLOCK) {
						RepeatBlockViolationEvidence nbve = (RepeatBlockViolationEvidence) evidence;
						reason = String.format("共识过程中,开始时间为%s的轮次重复出块,没收保证金%s", DateUtil.convertDate(new Date(nbve.getBlockHeaders().get(0).getPeriodStartTime() * 1000)), Coin.valueOf(vtx.getOutput(0).getValue()).toText());
						credit = Configure.CERT_CHANGE_SERIOUS_VIOLATION;
						isSendout = true;
					}
					detail += "信用 " + credit + " 原因：" + reason;
				} else if(tx.getType() == Definition.TYPE_REG_ALIAS) {
					//注册别名
					RegAliasTransaction ratx = (RegAliasTransaction) tx;
					
					type = "设置别名";
					
					for (Account account : accounts) {
						if(Arrays.equals(account.getAddress().getHash160(), ratx.getHash160())) {
							try {
								detail = "账户" + account.getAddress().getBase58() + "设置别名为：" + new String(ratx.getAlias(), "utf-8");
							} catch (UnsupportedEncodingException e) {
							}
							break;
						}
					}
				} else if(tx.getType() == Definition.TYPE_UPDATE_ALIAS) {
					//修改别名
					UpdateAliasTransaction uatx = (UpdateAliasTransaction) tx;
					
					type = "修改别名";
					
					for (Account account : accounts) {
						if(Arrays.equals(account.getAddress().getHash160(), uatx.getHash160())) {
							try {
								detail = "账户" + account.getAddress().getBase58() + "修改别名为：" + new String(uatx.getAlias(), "utf-8") + " ，信用" + Configure.UPDATE_ALIAS_SUB_CREDIT;
							} catch (UnsupportedEncodingException e) {
							}
							break;
						}
					}
				} else if(tx.getType() == Definition.TYPE_RELEVANCE_SUBACCOUNT) {
					//关联子账户
					RelevanceSubAccountTransaction rsatx = (RelevanceSubAccountTransaction) tx;
					
					type = "关联账户";
					
					detail += "关联子账户：" + rsatx.getAddress().getBase58();
					
				} else if(tx.getType() == Definition.TYPE_REMOVE_SUBACCOUNT) {
					//解除子账户的关联
					RemoveSubAccountTransaction rsatx = (RemoveSubAccountTransaction) tx;
					
					type = "关联解除";
					
					detail += "解除与账户：" + rsatx.getAddress().getBase58() + " 的关联";
					
				}
				else if(tx.getType() == Definition.TYPE_ASSETS_REGISTER) {
					//资产注册
					AssetsRegisterTransaction artx = (AssetsRegisterTransaction)tx;
					isSendout = true;
					type = "资产注册";
					detail += "名称：" + new String(artx.getName(), Utils.UTF_8) + "\n";
					detail += "描述：" + new String(artx.getDescription(), Utils.UTF_8) + "\n";
 					detail += "代码：" + new String(artx.getCode(), Utils.UTF_8) + "\n";
				}
				else if(tx.getType() == Definition.TYPE_ASSETS_ISSUED) {
					AssetsIssuedTransaction issuedTx = (AssetsIssuedTransaction)tx;
					type = "资产发行";
					TransactionStore txStore = LoanchainInstance.getInstance().getAccountKit().getTransaction(issuedTx.getAssetsHash());
					AssetsRegisterTransaction artx = (AssetsRegisterTransaction)txStore.getTransaction();
					detail += "名称：" + new String(artx.getName(), Utils.UTF_8) + "\n";
					detail += "代码：" + new String(artx.getCode(), Utils.UTF_8) + "\n";
					detail += "发行金额：" + issuedTx.getAmount() + "\n";
					AccountStore accountStore = LoanchainInstance.getInstance().getAccountKit().getAccountStore(issuedTx.getReceiver());
					Address address;
					if(accountStore == null) {
						address = new Address(network, issuedTx.getReceiver());
					}else {
						address = new Address(network,accountStore.getType(), issuedTx.getReceiver());
					}
					detail += "接收人：" + address.getBase58() + "\n";
				}

				else if(tx.getType() == Definition.TYPE_ASSETS_TRANSFER) {
					AssetsTransferTransaction transferTx = (AssetsTransferTransaction)tx;
					type = "资产转让";
					TransactionStore txStore = LoanchainInstance.getInstance().getAccountKit().getTransaction(transferTx.getAssetsHash());
					AssetsRegisterTransaction artx = (AssetsRegisterTransaction)txStore.getTransaction();
					detail += "名称：" + new String(artx.getName(), Utils.UTF_8) + "\n";
					detail += "代码：" + new String(artx.getCode(), Utils.UTF_8) + "\n";
					detail += "转让金额：" + transferTx.getAmount() + "\n";
					AccountStore accountStore = LoanchainInstance.getInstance().getAccountKit().getAccountStore(transferTx.getReceiver());
					Address address;
					if(accountStore == null) {
						address = new Address(network, transferTx.getReceiver());
					}else {
						address = new Address(network,accountStore.getType(), transferTx.getReceiver());
					}
					detail += "接收人：" + address.getBase58() + "\n";
				}else if(tx.getType() == Definition.TYPE_CERT_ACCOUNT_REVOKE){
					CertAccountRevokeTransaction revokeTx = (CertAccountRevokeTransaction)tx;
					type = "账户吊销";
					byte[] revokedhash = revokeTx.getRevokeHash160();
					Address raddress = new Address(network,network.getCertAccountVersion(),revokedhash);
					detail += "吊销账户："+raddress.getBase58()+"\n";
				}

				if(tx.isPaymentTransaction() && tx.getOutputs().size() > 0) {
					
					if(isSendout) {
						amount = "-" + Coin.valueOf(tx.getOutput(0).getValue()).toText();
					} else {
						amount = "+" + Coin.valueOf(tx.getOutput(0).getValue()).toText();
						
					}
				}
				time = DateUtil.convertDate(new Date(tx.getTime() * 1000), "yyyy-MM-dd HH:mm:ss");

				detailValue.setValue(detail);
				long confirmCount = 0;
				if(txs.getHeight() >= 0) {
					confirmCount = bestBlockHeight - txs.getHeight() + 1;
				}
				list.add(new TransactionEntity(tx.getHash(), confirmCount, type, detailValue, amount, time));
			}
		}
	}
	
	@Override
	public void onShow() {
	}

	@Override
	public void onHide() {
	}

	@Override
	public boolean refreshData() {
		return false;
	}

	@Override
	public boolean startupInit() {
		return true;
	}
}
