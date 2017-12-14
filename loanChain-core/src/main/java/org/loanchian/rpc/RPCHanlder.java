package org.loanchian.rpc;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.loanchian.account.AccountBody;
import org.loanchian.account.Address;
import org.loanchian.core.Coin;
import org.loanchian.core.Definition;
import org.loanchian.core.exception.AddressFormatException;
import org.loanchian.core.exception.ContentErrorExcetption;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.network.NetworkParams;
import org.loanchian.service.impl.VersionService;
import org.loanchian.utils.Base58;
import org.loanchian.utils.DateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * RPC命令分发处理
/**
 * 
 * 核心客户端RPC服务，RPC服务随核心启动，端口配置参考 {@link org.loanchian.Configure }
 * 命令列表：
 * help    帮助命令，列表出所有命令
 * 
 * --- 区块相关
 * getblockcount 				获取区块的数量
 * getnewestblockheight 		获取最新区块的高度 
 * getnewestblockhash			获取最新区块的hash
 * getblockheader [param] (block hash or height)	通过区块的hash或者高度获取区块的头信息
 * getblock		  [param] (block hash or height)	通过区块的hash或者高度获取区块的完整信息
 * 
 * --- 内存池
 * getmempoolinfo [count] 		获取内存里的count条交易
 * 
 * --- 帐户
 * newaccount [mgpw trpw]		创建帐户，同时必需指定帐户管理密码和交易密码
 * getaccountaddress			获取帐户的地址
 * getaccountpubkeys			获取帐户的公钥
 * dumpprivateseed 				备份私钥种子，同时显示帐户的hash160
 * 
 * getbalance					获取帐户的余额
 * gettransaction				获取帐户的交易记录
 * 
 * ---交易相关
 * TODO ···
 * 
 * @author ln
 *
 */
@Service
public class RPCHanlder {

	private final static Logger log = LoggerFactory.getLogger(org.loanchian.rpc.RPCHanlder.class);

	@Autowired
	private NetworkParams network;
	@Autowired
	private RPCService rpcService;
	@Autowired
	private VersionService versionService;

	/**
	 * 处理命令
	 * @param commandInfos
	 * @return JSONObject
	 * @throws JSONException
	 */
	public JSONObject hanlder(JSONObject commandInfos) throws JSONException {
		try {
			return hanlder(commandInfos, null);
		} catch (JSONException e) {
			return new JSONObject().put("success", false).put("message", "缺少参数");
		} catch (AddressFormatException ae) {
			return new JSONObject().put("success", false).put("message", "地址不正确");
		}
	}

	public JSONObject hanlder(JSONObject commandInfos, JSONObject inputInfos) throws JSONException {
		String command = commandInfos.getString("command");

		JSONArray params = commandInfos.getJSONArray("params");

		String password = null;
		String newPassword = null;
		if(inputInfos != null) {
			if(inputInfos.has("password")) {
				password = inputInfos.getString("password");
				if(inputInfos.has("newPassword")) {
					newPassword = inputInfos.getString("newPassword");
				}
			} else if(inputInfos.has("newPassword")) {
				password = inputInfos.getString("newPassword");
			}
		}

		JSONObject result = new JSONObject();
		switch (command) {

			//获取本地区块数量
			case "help":  {
				result.put("success", true);
				result.put("commands", getHelpCommands());

				return result;
			}

			//获取当前版本信息
			case "getversion":  {
				result.put("success", true);
				result.put("version", Definition.LIBRARY_SUBVER);

				String newestVersion = versionService.getNewestVersion();

				result.put("newestversion", newestVersion);

				return result;
			}

			//更新版本
			case "updateversion":  {
				result.put("success", true);

				JSONObject json = versionService.check();

				if(json.getBoolean("success") && json.getBoolean("newVersion")) {

					versionService.update(null);
					result.put("message", "更新成功，请重启客户端");

				} else {
					result.put("message", "无需更新");
				}

				return result;
			}

			//获取本地区块数量
			case "getblockcount":  {
				result.put("success", true);
				result.put("blockcount", rpcService.getBlockCount());

				return result;
			}

			//获取最新区块高度
			case "getbestblockheight": {
				result.put("success", true);
				result.put("bestblockheight", rpcService.getBestBlockHeight());

				return result;
			}

			//获取最新区块hash
			case "getbestblockhash": {
				result.put("success", true);
				result.put("bestblockhash", rpcService.getBestBlockHash());

				return result;
			}

			//通过高度获取区块hash
			case "getblockhash": {
				result.put("success", true);
				result.put("blockhash", rpcService.getBlockHashByHeight(Long.parseLong(params.getString(0))));

				return result;
			}

			//通过高度或者hash获取区块头信息
			case "getblockheader": {
			    if(params.length() != 1) {
			        return new JSONObject().put("success",false).put("message", "缺少参数");
                }
				return  rpcService.getBlockHeader(params.getString(0));
			}

			//通过hash或者高度获取一个完整的区块信息
			case "getblock": {
                if(params.length() != 1) {
                    return new JSONObject().put("success",false).put("message", "缺少参数");
                }
				return rpcService.getBlock(params.getString(0));
			}

			//通过hash获取一个分叉快
			case "getforkblock": {
				result.put("success", true);
				result.put("blockheader", rpcService.getForkBlock(params.getString(0)));

				return result;
			}

			//获取账户列表
			case "getaccounts": {
				JSONArray array = rpcService.getAccounts();

				result.put("success", true);
				result.put("accountList", array);

				return result;
			}

			//新建普通账户
			case "newaccount": {
				int count = 1;
				if(params.length()==0){
					count = 1;
				}else {
					count = params.getInt(0);
				}
				if(count>50000){
					result.put("success", false);
					result.put("message", "参数不正确，每次最多生成50000个账户地址");
					return result;
				}
				try {
					result = rpcService.newAccount(count);
				} catch (IOException e) {
					result.put("success", false);
					result.put("message", "创建时出错：" + e.getMessage());
				}

				return result;
			}

			//新建认证账户
			case "newcertaccount": {
				if(params.length()<4){
					result.put("success", false);
					result.put("message", "缺少参数，命令用法：newcertaccount [mgpw] [trpw] [body hex] [managerMgPw]");
					return result;
				}
				try {
					String mggpw = params.getString(0);
					String trpw = params.getString(1);
					String bodyHexStr = params.getString(2);
					AccountBody body = new AccountBody(Base58.decode(bodyHexStr));
					String certpw = params.getString(3);
					String managerAddress = null;
					if(params.length()==5) {
						managerAddress = params.getString(4);
					}

					result = rpcService.newCertAccount(mggpw, trpw, body,certpw,managerAddress);
				} catch (Exception e) {
					if(e instanceof JSONException ||e instanceof ContentErrorExcetption) {
						result.put("success", false);
						result.put("message", "缺少参数，命令用法：newcertaccount [mgpw] [trpw] [body hex] [managerMgPw]");
						return result;
					}
					result.put("success", false);
					result.put("message", "创建时出错：" + e.getMessage());
				}

				return result;
			}

			//修改认证账户信息
			case "updatecertaccount": {

				try {
					String bodyHexStr = params.getString(0);
					AccountBody body = new AccountBody(Base58.decode(bodyHexStr));
					String pw = params.getString(1);
					String address = null;
					if(params.length() > 2) {
						address = params.getString(2);
					}

					result = rpcService.updateCertAccount(body, pw, address);
				} catch (Exception e) {
					if(e instanceof JSONException ||e instanceof ContentErrorExcetption) {
						result.put("success", false);
						result.put("message", "缺少参数，命令用法：updatecertaccount [body hex] [pw]");
						return result;
					}
					result.put("success", false);
					result.put("message", "创建时出错：" + e.getMessage());
				}

				return result;
			}

			//吊销认证账户信息
			case "revokecertaccount": {

				try {
					String revokeAddress = params.getString(0);
					String pw = params.getString(1);
					String address = params.getString(2);
					result = rpcService.revokeCertAccount(revokeAddress, pw, address);
				} catch (JSONException e) {
					if(e instanceof JSONException) {
						result.put("success", false);
						result.put("message", "缺少参数，命令用法：revokecertaccount [revokeaddress] [trpw] [address]");
						return result;
					}
					result.put("success", false);
					result.put("message", "创建时出错：" + e.getMessage());
				}

				return result;
			}

			//修改认证账户密码
			case "certaccounteditpassword": {

				try {
					String oldMgpw = params.getString(0);
					String newMgpw = params.getString(1);
					String newTrpw = params.getString(2);
					String address = null;
					if(params.length() > 3) {
						address = params.getString(3);
					}

					result = rpcService.certAccountEditPassword(oldMgpw, newMgpw, newTrpw, address);
				} catch (JSONException e) {
					if(e instanceof JSONException) {
						result.put("success", false);
						result.put("message", "缺少参数，命令用法：newcertaccount [mgpw] [trpw] [body hex]");
						return result;
					}
					result.put("success", false);
					result.put("message", "创建时出错：" + e.getMessage());
				}

				return result;
			}

			//获取余额
			case "getbalance": {

				String address = null;

				if(params.length() > 0) {
					address = params.getString(0);
				}

				Coin[] balances = rpcService.getAccountBalance(address);

				result.put("success", true);
				result.put("balance", balances[0].add(balances[1]).value);
				result.put("canUseBalance", balances[0].value);
				result.put("cannotUseBalance", balances[1].value);

				return result;
			}

			//获取所有账户总余额
			case "gettotalbalance": {

				String address = null;

				if(params.length() > 0) {
					address = params.getString(0);
				}

				Coin[] balances = rpcService.getTotalBalance();

				result.put("success", true);
				result.put("balance", balances[0].add(balances[1]).value);
				result.put("canUseBalance", balances[0].value);
				result.put("cannotUseBalance", balances[1].value);

				return result;
			}

			//获取账户信用
			case "getcredit": {
				try {
					String address = null;

					if(params.length() > 0) {
						address = params.getString(0);
					}

					long credit = rpcService.getAccountCredit(address);

					result.put("success", true);
					result.put("credit", credit);
				} catch (VerificationException e) {
					result.put("success", false);
					result.put("message", e.getMessage());
				}
				return result;
			}

			//获取账户信息
			case "getaccountinfo": {
				try {
					String address = null;

					if(params.length() > 0) {
						address = params.getString(0);
					}

					result = rpcService.getAccountInfo(address);

					result.put("success", true);
				} catch (VerificationException e) {
					result.put("success", false);
					result.put("message", e.getMessage());
				}
				return result;
			}

			//加密钱包
			case "encryptwallet": {
				if(password == null && params.length() >= 1) {
					password = params.getString(0);
				}
				result = rpcService.encryptWallet(password);
				return result;
			}

			//修改密码
			case "password": {
				if(password == null && newPassword == null && params.length() >= 2) {
					password = params.getString(0);
					newPassword = params.getString(1);
				}
				result = rpcService.changePassword(password, newPassword);
				return result;
			}

			//通过hash获取一笔交易详情
			case "gettx": {
				try {
					result = rpcService.getTx(params.getString(0));
				}catch (Exception e) {
					result.put("success", false);
					result.put("message", "not found");
				}
				return result;
			}

			case "lockwallet":{
				return rpcService.lockWallet();
			}
			case "unlockwallet":{
				if(params.length()!=2){
					result.put("success", false);
					result.put("message", "缺少参数，命令用法：unlockwallet password timeout");
					return result;
				}
				String passwd = params.getString(0);
				int timeSec = 0;
				try {
					timeSec = Integer.parseInt(params.getString(1));
					if(timeSec<0){
						throw new Exception();
					}
				}catch (Exception e){
					result.put("success", false);
					result.put("message", "参数错误：timeout是解锁钱包的秒数(int)");
					return result;
				}
				return rpcService.unlockWallet(passwd,timeSec);
			}


			case "gettransfertx" : {
				if(params.length() == 0) {
					result.put("success", false);
					result.put("message", "缺少参数，命令用法：gettransfertx <height> [confirm] [address]");
					return result;
				}

				Long height = null;
				Long confirm = 0L;              //默认确认高度为0
				String address = null;
				try {
					if(params.length() == 1) {
						height = params.getLong(0);
					}
					else if(params.length() == 2) {
						height = params.getLong(0);
						try {
							confirm = params.getLong(1);
						}catch (Exception e) {
							address = params.getString(1);
						}
					}
					else if(params.length() > 2) {
						height = params.getLong(0);
						confirm = params.getLong(1);
						address = params.getString(2);
					}
					//检查地址是否合法
					if(address != null) {
						Address ar = Address.fromBase58(network, address);
					}
				}catch (Exception e) {
					result.put("success", false);
					result.put("message", "参数错误，命令用法：gettransfertx <height> [confirm] [address]");
					return result;
				}

				JSONArray txs = rpcService.getTransferTx(height, confirm, address);

				result.put("success", true);
				result.put("txs", txs);

				return result;
			}

			//获取交易记录
			case "listtransactions": {
				if(params.length() == 0) {
					result.put("success", false);
					result.put("message", "缺少参数，命令用法：listtransactions <limit> [confirm] [address]");
					return result;
				}

				int limit = 0;
				int confirm = 0;
				String address = null;
				try {
					if(params.length() == 1) {
						limit = params.getInt(0);
					}else if(params.length() == 2) {
						limit = params.getInt(0);
						try {
							confirm = params.getInt(1);
						}catch (Exception e) {
							address = params.getString(1);
						}
					}else if(params.length() > 2) {
						limit = params.getInt(0);
						confirm = params.getInt(1);
						address = params.getString(2);
					}
					//检查地址是否合法
					if(address != null) {
						Address ar = Address.fromBase58(network, address);
					}
				}catch (Exception e) {
					result.put("success", false);
					result.put("message", "参数格式错误，命令用法：listtransactions <count> [confirm] [address]");
					return result;
				}


				JSONArray txs =  rpcService.listtransactions(limit, confirm, address);
				result.put("success", true);
				result.put("txs", txs);
				return result;
			}


			//获取账户交易
			case "gettransaction": {
				String address = null;

				if(params.length() > 0) {
					address = params.getString(0);
				}

				JSONArray txs = rpcService.getTransaction(address);

				result.put("success", true);
				result.put("txs", txs);

				return result;
			}

			//转账
			case "send": {

				if(params.length() < 3) {
					return new JSONObject().put("success", false).put("message", "缺少参数");
				}

				String toAddress = params.getString(0);
				String amount = params.getString(1);
				String address = params.getString(2);
				String remark = null;
				String passwordOrRemark = null;

				if(params.length() == 4) {
					passwordOrRemark = params.getString(3);
				} else if(params.length() == 5) {
					password = params.getString(3);
					remark = params.getString(4);
				}

				try {
					Address a = new Address(network, toAddress);
				} catch (Exception e) {
					return new JSONObject().put("success", false).put("message", "接收人地址有误");
				}

				return rpcService.sendMoney(toAddress, amount, address, password, remark, passwordOrRemark);
			}

			//多用户向同一个地址转账
			case "sendtoaddress": {

				if(params.length() < 2) {
					return new JSONObject().put("success", false).put("message", "缺少参数");
				}

				String toAddress = params.getString(0);
				String amount = params.getString(1);
				String pass = null;
				String remark = null;


				if(params.length() == 4) {
					pass = params.getString(2);
					remark = params.getString(3);
				}

				if(params.length() == 3){
					pass = params.getString(2);
				}
				try {
					Address a = new Address(network, toAddress);
				} catch (Exception e) {
					return new JSONObject().put("success", false).put("message", "接收人地址有误");
				}
				JSONArray toaddressAndCoins = new JSONArray();
				toaddressAndCoins.put(new JSONObject().put(toAddress,amount));
				return rpcService.sendMoneyToAddress(toaddressAndCoins,pass,remark);
			}

			case "sendmoney": {
				if(params.length() < 1) {
					return new JSONObject().put("success", false).put("message", "缺少参数");
				}

				String toaddressAndCoinsStr = params.getString(0);
				JSONArray toaddressAndCoins = null;
				try {
					toaddressAndCoins = new JSONArray(toaddressAndCoinsStr);
				}catch (Exception e ){
					return new JSONObject().put("success", false).put("message", "参数格式错误");
				}
				String pass = null;
				String remark = null;

				if(params.length() == 2){
					pass = params.getString(1);
				}

				if(params.length() == 3) {
					pass = params.getString(1);
					remark = params.getString(2);
				}

				return rpcService.sendMoneyToAddress(toaddressAndCoins,pass,remark);
			}

			//发放锁仓奖励
			case "lockreward": {
				if(params.length() < 6) {
					return new JSONObject().put("success", false).put("message", "缺少参数");
				}

				String toAddress = params.getString(0);
				String amount = params.getString(1);
				long lockTime = params.getLong(2);

				String remark = params.getString(3);
				String address = params.getString(4);
				password = params.getString(5);

				try {
					Address.fromBase58(network, toAddress);
				}catch (Exception e) {
					result.put("success", false);
					result.put("message", "接收人地址有误");
				}

				try {
					Address.fromBase58(network, address);
				}catch (Exception e) {
					result.put("success", false);
					result.put("message", "转账人地址有误");
				}

				Coin lockValue;
				try {
					lockValue = Coin.parseCoin(amount);
				} catch (Exception e) {
					result.put("success", false);
					result.put("message", "错误的金额");
					return result;
				}

				if(StringUtils.isEmpty(password)) {
					result.put("success", false);
					result.put("message", "请输入密码");
					return result;
				}

				return rpcService.lockReward(toAddress, lockValue, address, password, remark, lockTime);
			}

			//锁仓
			case "lockmoney": {

				if(params.length() < 3) {
					return new JSONObject().put("success", false).put("message", "缺少参数");
				}

				String amount = params.getString(0);
				String lockTimeStr = params.getString(1);
				String remark = params.getString(2);
				String address = null;

				if(params.length() == 4) {
					address = params.getString(3);
					try {
						Address.fromBase58(network, address);
					} catch (Exception e) {
						password = address;
						address = null;
					}
				} else if(params.length() == 5) {
					address = params.getString(3);
					try {
						Address ar = Address.fromBase58(network, address);
						password = params.getString(4);
					} catch (Exception e) {
						result.put("success", false);
						result.put("message", "缺少参数，命令用法：lockmoney <money> <unlockTime> <remark> [address] [password]，日期格式为yyyy-MM-dd");
						return result;
					}
				}
				Coin lockValue = Coin.ZERO;
				long lockTime = 0L;
				try {
					lockValue = Coin.parseCoin(amount);
				} catch (Exception e) {
					result.put("success", false);
					result.put("message", "错误的锁仓金额，命令用法：lockmoney <money> <unlockTime> <remark> [address] [password]，日期格式为yyyy-MM-dd");
					return result;
				}
				try {
					lockTime = DateUtil.convertStringToDate(lockTimeStr, "yyyy-MM-dd").getTime() / 1000;
				} catch (Exception e) {
					result.put("success", false);
					result.put("message", "错误的日期，命令用法：lockmoney <money> <unlockTime> <remark> [address] [password]，日期格式为yyyy-MM-dd");
					return result;
				}

				return rpcService.lockMoney(lockValue, lockTime, address, password, remark);
			}

		//广播
		case "broadcast": {
			if(params.length() == 0) {
				result.put("success", false);
				result.put("message", "缺少参数");
				return result;
			}
			
			return rpcService.broadcast(params.getString(0));
		}

		//广播交易
		case "broadcastrantx" : {
			if(params.length() != 1) {
				result.put("success", false);
				result.put("message", "缺少参数");
				return result;
			}
			try {
				JSONObject param = new JSONObject(params.getString(0));

				String amount = param.getString("amount");
				String privateKey = param.getString("privateKey");
				String toAddress = param.getString("to");
				String remark = param.getString("remark");
				JSONArray jsonArray = null;
				try {
					jsonArray = param.getJSONArray("utxos");
				}catch (Exception e) {
					e.printStackTrace();
					result.put("success", false);
					result.put("message", "参数格式有误");
					return result;
				}
				return rpcService.broadcastTransferTransaction(amount, privateKey, toAddress, remark, jsonArray);
			}catch (Exception e) {
				log.error("广播交易错误", e);
				result.put("success", false);
				result.put("message", "广播交易失败");
				return result;
			}

		}

		
		//广播交易，交易存于文件里
		case "broadcastfromfile": {
			if(params.length() == 0) {
				result.put("success", false);
				result.put("message", "缺少参数");
				return result;
			}
			
			return rpcService.broadcastfromfile(params.getString(0));
		}
		
		//获取共识列表
		case "getconsensus": {
			JSONArray consensus = rpcService.getConsensus();
			
			result.put("success", true);
			result.put("consensus", consensus);
			
			return result;
		}
		
		//获取当前共识节点数量
		case "getconsensuscount": {
			return rpcService.getConsensusCount();
		}
		
		//查看当前共识状态
		case "getconsensusstatus": {
			return rpcService.getConsensusStatus();
		}
		
		//注册共识
		case "regconsensus": {
			String consensusAddress = null;
			if(params.length() == 1) {
				String param1 = params.getString(0);
				try {
					Address.fromBase58(network, param1);
					consensusAddress = param1;
				} catch (Exception e) {
					password = params.getString(0);
				}
			}
			if(params.length() == 2) {
				consensusAddress = params.getString(0);
				password = params.getString(1);
			}
			result = rpcService.regConsensus(password, consensusAddress);
			return result;
		}
		//查询共识保证金
		case "getregconsensusfee": {
			return rpcService.regconsensusFee();
		}

		//退出共识
		case "remconsensus": {
			String address = null;
			if(params.length()  == 1){
				address = params.getString(0);
			}else if(params.length() == 2){
				address = params.getString(0);
				password = params.getString(1);
			}else {
				result.put("success",false);
				result.put("message","remconsensus address [password]");
				return result;
			}


			result = rpcService.remConsensus(address,password);
			return result;
		}
		
		//获取连接节点信息
		case "getpeers": {
			result = rpcService.getPeers();
			
			result.put("success", true);
			return result;
		}
		
		//获取连接节点数量
		case "getpeercount": {
			result = rpcService.getPeerCount();
			
			result.put("success", true);
			return result;
		}
		
		//通过公钥得到地址
		case "getaddressbypubkey": {
			String pubkey = params.getString(0);
			return rpcService.getAddressByPubKey(pubkey);
		}


		//验证地址
		case "validateaddress": {
			if(params.length() == 0) {
				result.put("success", false);
				result.put("message", "缺少参数，命令用法：validateaddress <address>");
				return result;
			}

			String address = params.getString(0);
			try {
				Address.fromBase58(network, address);
			} catch (Exception e) {
				result.put("success", false);
				result.put("message", "地址格式错误");
				return result;
			}

			return rpcService.validateAddress(address);
		}

		//查看账户的私钥
		case "getprivatekey": {
			
			String pwd = null;
			String address = null;
			if(params.length() == 1) {
				//当参数只有一个时，判断是密码还是地址
				try {
					Address.fromBase58(network, address);
					address = params.getString(0);
					pwd = null;
				} catch (Exception e) {
					pwd = params.getString(0);
				}
			}else if(params.length() > 1) {
				address = params.getString(0);
				pwd = params.getString(1);
			}
			return rpcService.getPrivatekey(address, pwd);
		}
		
		//查看账户的私钥
		case "resetdata": {
			return rpcService.resetData();
		}
		
		default:
			result.put("success", false).put("message", "没有找到的命令" + command);
			return result;
		}
	}

	/*
	 * 获取帮助命令
	 */
	public static String getHelpCommands() {
		StringBuilder sb = new StringBuilder();
		
		sb.append("命令列表\n");
		sb.append("\n");
		sb.append(" --- 区块相关 --- \n");
		sb.append("  getblockcount                                                                                                                   获取区块的数量\n");
		sb.append("  getbestblockheight                                                                                                    获取最新区块的高度\n");
		sb.append("  getbestblockhash                                                                                                      获取最新区块的hash\n");
		sb.append("  getblockhash <height>                                                                                         通过高度获取区块hash\n");
		sb.append("  getblockheader <block hash or height>                                通过区块的hash或者高度获取区块的头信息\n");
		sb.append("  getblock <block hash or height>                                        通过区块的hash或者高度获取区块的完整信息\n");
		sb.append("\n");
		sb.append(" --- 帐户相关 --- \n");
		sb.append("  getbalance                                                                                                                        获取账户的余额\n");
		sb.append("  getcredit                                                                                                                           获取账户的信用\n");
		sb.append("  getaccountinfo                                                                                                           获取账户的详细信息\n");
		sb.append("  importprikey                                                                                                           把私钥导入账户到钱包\n");

		sb.append("  getaccounts                                                                                                              获取钱包所有账户列表\n");
		sb.append("  encryptwallet <password>                                                                                                         加密钱包\n");
		sb.append("  password <password> <new password>                                                                           修改钱包密码\n");
		sb.append("  getprivatekey [address] [password]                                                                                 查看账户的私钥\n");
		sb.append("  getaddressbypubkey <pubkey> 			                                                          通过账户公钥获取地址\n");
		sb.append("  unlockwallet <password> <timeout> 			                                                          解锁钱包timeout秒\n");
		sb.append("  lockwallet  			                                                          								立即锁定钱包\n");

		sb.append("\n");
		sb.append(" --- 交易相关 --- \n");
		sb.append("  gettx <tx hash>                                                                                       通过交易hash获取一条交易详情\n");
		sb.append("  send <to address> <coin> <my address> [password] [remark]    										转账\n");
		sb.append("  sendtoaddress <to address> <coin> [password]  [remark]                                                使用钱包给指定地址转账\n");
		sb.append("  sendmoney <toaddressandcoins> [password]  [remark]                                                使用钱包给指定地址转账\n");
		sb.append("  lockmoney <money> <unlockTime(yyyy-MM-dd)> <remark> [address] [password]             锁仓交易\n");
		sb.append("  listtransactions <limit> [confirm] [address]                                                       获取账户的代币交易记录\n");
		sb.append("  gettransaction                                                                                                            获取帐户的交易记录\n");

		sb.append("\n");
		sb.append(" --- 共识相关 --- \n");
		sb.append("  getconsensus                                                                                                                获取共识节点列表\n");
		sb.append("  getconsensuscount                                                                                                       获取共识节点数量\n");
		sb.append("  getconsensusstatus                                                                                                       获取当前共识状态\n");
		sb.append("  getregconsensusfee                                                                                     获取当前参与共识所需保证金\n");
		sb.append("  regconsensus <consensusAddress> [password]                                                                       注册共识\n");
		sb.append("  remconsensus <consensusAddress> [password]                                                                      退出共识\n");

		sb.append("\n");
		sb.append(" --- 节点相关 --- \n");
		sb.append("  getpeers                                                                                                                        获取连接节点列表\n");
		sb.append("  getpeercount                                                                                                                获取连接节点数量\n");

		sb.append("\n");
		sb.append(" --- 业务相关 --- \n");
		sb.append("  createproduct <productinfo> <password> [address]                   认证账户创建商品[仅适用于认证账户]\n");
		sb.append("  queryantifake <antifakecode>              查询包括防伪码所属商家、商品、溯源、流转、验证、转让等信息\n");
		sb.append("  addcirculation <antifakecode> <subject> <description> [address] [password]                  防伪码流转 \n");
		sb.append("  querycirculations <antifakecode>                                                                            查询防伪码流转信息\n");
		sb.append("  querycirculationcount <antifakecode> [address]                                                     查询防伪码流转次数\n");
		sb.append("  transferantifake <antifakecode> <receiver> <description> [address] [password]               防伪码转让\n");
		sb.append("  querytransfers <antifakecode>                                                                                 查询防伪码转让记录\n");
		sb.append("  querytransfercount <antifakecode>                                                                         查询防伪码转让次数\n");
		sb.append("  queryantifakeowner <antifakecode>                                                                           查询防伪码拥有者\n");
		//sb.append("  makegeneralantifakecode [productinfo|producttxid] [password]         创建普通防伪码[仅适用于认证账户]\n");
		//sb.append("  makeantifakecode [productinfo] [password]                            创建链上防伪码[仅适用于认证账户]\n");
		//sb.append("  verifygeneralantifakecode [antifakecode] [password]                  验证普通防伪码[仅适用于普通账户]\n");
		//sb.append("  verifyantifakecode [antifakecode] [password]                         验证链上防伪码[仅适用于普通账户]\n");

		sb.append("\n");
		sb.append("  relevancesubaccount <address> <alias> <description> <password> [certAddress]           关联子账户\n");
		sb.append("  removesubaccount <address> <txHash> <password> [certAddress]                        解除子账户的关联\n");
		sb.append("  getsubaccounts <certAddress>                                                                         获取认证商家子账户列表\n");
		sb.append("  getsubaccountcount <certAddress>                                                                 获取认证商家子账户数量\n");
		sb.append("  checkissubaccount <certAddress> <address>                                                  检查是否是商家的子账户\n");
		sb.append("\n");
		sb.append(" --- 资产相关 --- \n");
		sb.append("  regassets <name> <description> <code> <logo> <remark> [address] [password]               资产注册\n");
		sb.append("  getassetslist                                                                                                                   查询资产注册列表\n");
		sb.append("  assetsissue <code> <receiver> <amount> <remark> [address] [password]                           资产发行\n");
		sb.append("  getassetsissuelist <code>                                                                                             查询资产发行列表\n");
		sb.append("  getmineassets [address] [password]                                                                      查询我的账户资产列表\n");
		sb.append("  assetstransfer <code> <receiver> <amount> <remark> [address] [password]                       资产转让\n");
		sb.append("\n");
		sb.append(" --- 系统相关 --- \n");
		sb.append("  getversion                                                                                                                     获取系统版本信息\n");
		sb.append("  updateversion                                                                                                                            更新版本\n");




		return sb.toString();
	}
}    
   
