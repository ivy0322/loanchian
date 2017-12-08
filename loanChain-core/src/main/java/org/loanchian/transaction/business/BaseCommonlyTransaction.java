package org.loanchian.transaction.business;

import org.loanchian.account.Account;
import org.loanchian.account.Address;
import org.loanchian.core.Definition;
import org.loanchian.core.VarInt;
import org.loanchian.core.exception.AccountEncryptedException;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.ECKey;
import org.loanchian.crypto.ECKey.ECDSASignature;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;
import org.loanchian.script.Script;
import org.loanchian.script.ScriptBuilder;
import org.loanchian.transaction.Transaction;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 其它交易均继承该类
 * @author ln
 *
 */
public abstract class BaseCommonlyTransaction extends Transaction {

	//签名
	protected byte[] scriptBytes;
	//签名验证脚本
	protected Script scriptSig;
		
	public BaseCommonlyTransaction(NetworkParams network) {
		super(network);
	}
	
	public BaseCommonlyTransaction(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
		this(params, payloadBytes, 0);
    }
	
	public BaseCommonlyTransaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
		super(params, payloadBytes, offset);
	}
	
	/**
	 * 序列化
	 */
	@Override
	protected void serializeToStream(OutputStream stream) throws IOException {
		serializeHeadToStream(stream);
		serializeBodyToStream(stream);
	}


	protected void serializeHeadToStream(OutputStream stream) throws IOException {
		super.serializeToStream(stream);
		
		//签名
		if(scriptBytes != null) {
			stream.write(new VarInt(scriptBytes.length).encode());
			stream.write(scriptBytes);
		}else{
			stream.write(new VarInt(0).encode());
		}
	}

	protected void serializeBodyToStream(OutputStream stream) throws IOException {

	}

	
	/**
	 * 反序列化，BaseCommonlyTransaction涉及代币的交易remark字段已经在父类处理
	 */
	@Override
	protected void parse()throws ProtocolException{
		parseHead();
		parseBody();
		length = cursor - offset;
	}

	/*
		凡是继承BaseCommonlyTransactin 都涉及代币交易，parsehead反序列化代币交易,然后反序列化公共头部
	*/
	protected void parseHead()throws ProtocolException{
		super.parse();

		int  scriptLen = (int)readVarInt();
		if(scriptLen>0) {
			this.scriptBytes = readBytes(scriptLen);
			this.scriptSig = new Script(this.scriptBytes);
		}else {
			this.scriptBytes = null;
			this.scriptSig = null;
		}
	}

	protected void parseBody() throws ProtocolException {

	}
	
	/**
	 * 验证交易的合法性
	 */
	public void verify() throws VerificationException {
		if(scriptBytes == null && scriptSig == null) {
			throw new VerificationException("验证脚本不存在");
		}
		if(scriptSig == null) {
			scriptSig = new Script(scriptBytes);
		}
	}

	/**
	 * 验证交易脚本
	 */
	public void verifyScript() {
		verfifyCommonScript();
	}
	
	protected void verfifyCommonScript() {
		//除转账交易外的通用验证脚本
		BaseCommonlyTransaction tempTransaction = (BaseCommonlyTransaction) network.getDefaultSerializer().makeTransaction(baseSerialize(), 0);
		tempTransaction.setScriptBytes(null);
		tempTransaction.getScriptSig().runVerify(tempTransaction.getHash());
	}
    
    /**
     * 除转帐交易外的其它交易，通用的签名方法
	 * 如果账户已加密的情况，则需要先解密账户
     * 如果是认证账户，默认使用交易的签名，如需使用账户管理签名，则调用sign(account, TransactionDefinition.TX_VERIFY_MG)
     * @param account
     */
	public void sign(Account account) {
		sign(account, Definition.TX_VERIFY_TR);
	}
	
	/**
	 * 除转帐交易外的其它交易，通用的签名方法
	 * 如果账户已加密的情况，则需要先解密账户
	 * @param account
	 * @param type Definition.TX_VERIFY_MG利用管理私钥签名，Definition.TX_VERIFY_TR利用交易私钥签名
	 */
	public void sign(Account account, int type) {
		hash = null;
		hash = getHash();
		scriptBytes = null;

		//是否加密
		if(!account.isCertAccount() && account.isEncrypted()) {
			throw new AccountEncryptedException();
		}
		if(account.isCertAccount()) {
			if(type == Definition.TX_VERIFY_MG && account.isEncryptedOfMg()) {
				throw new AccountEncryptedException();
			} else if(type == Definition.TX_VERIFY_TR && account.isEncryptedOfTr()) {
				throw new AccountEncryptedException();
			}
		}
		
		if(account.isCertAccount()) {
			//认证账户
			if(account.getAccountTransaction() == null && account.getTxhash() == null) {
				throw new VerificationException("签名失败，认证账户没有对应的信息交易");
			}
			
			ECKey[] keys = null;
			if(type == Definition.TX_VERIFY_MG) {
				keys = account.getMgEckeys();
			} else {
				keys = account.getTrEckeys();
			}
			
			if(keys == null) {
				throw new VerificationException("账户没有解密?");
			}
			
			ECDSASignature ecSign = keys[0].sign(hash);
			byte[] sign1 = ecSign.encodeToDER();

			//facjas
			//ecSign = keys[1].sign(hash);
			byte[] sign2 = new byte[0];

			if(type == Definition.TX_VERIFY_MG){
				ecSign = keys[1].sign(hash);
				sign2 = ecSign.encodeToDER();
			}
			
			Sha256Hash txhash = null;
			
			if(account.getAccountTransaction() != null) {
				txhash = account.getAccountTransaction().getHash();
			} else {
				txhash = account.getTxhash();
			}
			
			scriptSig = ScriptBuilder.createCertAccountScript(type, txhash, account.getAddress().getHash160(), sign1, sign2);
			//scriptSig = ScriptBuilder.createCertAccountScript(type, Sha256Hash.wrap("474b0c43c0caa173830dcac976a26dcb6181c6de533d6e4f058bedb7e8f6189d"), Hex.decode("2b59fb5a63c362ead608707ee8641dec80eca302"), sign1, sign2);
		} else {
			//普通账户
			ECKey key = account.getEcKey();
			
			ECDSASignature ecSign = key.sign(hash);
			byte[] sign = ecSign.encodeToDER();
			
			scriptSig = ScriptBuilder.createSystemAccountScript(account.getAddress().getHash160(), key.getPubKey(true), sign);
		}
		scriptBytes = scriptSig.getProgram();
		
		hash = null;
		length += scriptBytes.length;
	}
	
	/**
	 * 获取交易发起账户的hash160
	 * @return byte[]
	 */
	public byte[] getHash160() {
		if(scriptSig == null) {
			throw new VerificationException("交易验证脚本不存在，无法获取账户hash160");
		}
		return scriptSig.getAccountHash160();
	}
	
	/**
	 * 获取交易者的账户地址
	 * @return String
	 */
	public String getOperator() {
		if(isCertAccount()) {
			return new Address(network, network.getCertAccountVersion(), getHash160()).getBase58();
		} else {
			return new Address(network, network.getSystemAccountVersion(), getHash160()).getBase58();
		}
	}
	
	/**
	 * 获取交易发起账户压缩过的公钥
	 * 通过签名脚本获取
	 * 仅支持普通系统账户，直接在签名脚本里获取
	 * 若需获取认证账户的公钥，需在链上查询，调用 {@link org.loanchian.store.ChainstateStoreProvider} 中的 getAccountPubkeys方法 获取认证账户的最新公钥
	 * @return byte[]
	 */
	public byte[] getPubkey() {
		if(scriptSig == null) {
			throw new VerificationException("交易验证脚本不存在，无法获取账户公钥");
		}
		if(!isSystemAccount()) {
			throw new RuntimeException("该方法不能获取认证账户的公钥， 请调用org.loanchian.store.ChainstateStoreProvider中的getAccountPubkeys获取");
		}
		return scriptSig.getAccountPubkey();
	}
	
	/**
	 * 是否是认证账户发起的交易
	 * 通过签名脚本判断
	 * @return boolean
	 */
	public boolean isCertAccount() {
		if(scriptSig == null) {
			throw new VerificationException("交易验证脚本不存在，无法判断其账户类型");
		}
		return scriptSig.isCertAccount();
	}
	
	/**
	 * 是否是普通系统账户发起的交易
	 * 通过签名脚本判断
	 * @return boolean
	 */
	public boolean isSystemAccount() {
		if(scriptSig == null) {
			throw new VerificationException("交易验证脚本不存在，无法判断其账户类型");
		}
		return scriptSig.isSystemAccount();
	}
	
	public byte[] getScriptBytes() {
		return scriptBytes;
	}

	public void setScriptBytes(byte[] scriptBytes) {
		this.scriptBytes = scriptBytes;
	}

	public Script getScriptSig() {
		return scriptSig;
	}

	public void setScriptSig(Script scriptSig) {
		this.scriptSig = scriptSig;
	}
}
