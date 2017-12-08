package org.loanchian.transaction;

import org.loanchian.Configure;
import org.loanchian.account.Address;
import org.loanchian.core.*;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.ECKey;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.crypto.TransactionSignature;
import org.loanchian.message.Message;
import org.loanchian.network.NetworkParams;
import org.loanchian.script.Script;
import org.loanchian.script.ScriptOpCodes;
import org.loanchian.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * 交易
 * @author ln
 *
 */
public class Transaction extends Message {

	//锁定时间标识，小于该数表示为块数，大于则为秒级时间戳
	public static final int LOCKTIME_THRESHOLD = 500000000;

    public static final BigInteger LOCKTIME_THRESHOLD_BIG = BigInteger.valueOf(LOCKTIME_THRESHOLD);

    //允许的交易最大值
    public static final int MAX_STANDARD_TX_SIZE = 100000;
    
    //tx hash
    protected Sha256Hash hash;

	//交易输入
    protected List<TransactionInput> inputs;

	//交易输出
    protected List<TransactionOutput> outputs;

	//交易时间
	protected long time;

	//锁定时间，小于0永久锁定，大于等于0为锁定的时间或者区块高度
	protected long lockTime;

	//交易版本
	protected long version;

	//交易类型
	protected int type;

	//备注
	protected byte[] remark;
	
	/**
	 * 签名类型
	 * @author ln
	 *
	 */
	public enum SigHash {
		//对整个交易签名
        ALL(1),
        //只签名输入部分
        SING_INPUT(2),
        
        NONE(3);

        public final int value;

        private SigHash(final int value) {
            this.value = value;
        }

        public byte byteValue() {
            return (byte) this.value;
        }
    }
	
	public Transaction(NetworkParams network) {
		super(network);
		inputs = new ArrayList<TransactionInput>();
        outputs = new ArrayList<TransactionOutput>();
        time = TimeService.currentTimeSeconds();
        version = Definition.VERSION;
	}

	public Transaction(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }

	public Transaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
        super(params, payloadBytes, offset);
    }
	
	/**
	 * 该协议是否新增协议，用于支持旧版本，就版本会解析成为UnkonwTransaction
	 * 当发布第一个版本之后，后面所有新增的协议，需覆盖该方法，并返回true
	 * 当需要兼容时，会在type后面带上长度
	 */
	public boolean isCompatible() {
		return false;
	}

	/**
	 * 序列化
	 */
	protected void serializeToStream(OutputStream stream) throws IOException {
		stream.write(type);
		Utils.uint32ToByteStreamLE(version, stream);
        stream.write(new VarInt(inputs.size()).encode());
        for (Input in : inputs)
            in.serialize(stream);
        stream.write(new VarInt(outputs.size()).encode());
        for (Output out : outputs)
            out.serialize(stream);
        Utils.uint32ToByteStreamLE(time, stream);
        Utils.uint32ToByteStreamLE(lockTime, stream);
        if(remark == null) {
        	stream.write(new VarInt(0).encode());
        }else if(remark.length>Configure.MAX_REMARK_LEN){
			stream.write(new VarInt(Configure.MAX_REMARK_LEN).encode());
			stream.write(remark,0,Configure.MAX_REMARK_LEN);
		} else{
        	stream.write(new VarInt(remark.length).encode());
        	stream.write(remark);
        }
    }
	
	/**
	 * 反序列化交易
	 */
	@Override
	protected void parse() throws ProtocolException {
		cursor = offset;
		
		type = readBytes(1)[0] & 0XFF;
		version = readUint32();
		
		if(isCompatible()) {
			length = (int) readUint32();
		}
		
		//交易输入数量
        long numInputs = readVarInt();
        inputs = new ArrayList<TransactionInput>((int) numInputs);
        for (int i = 0; i < numInputs; i++) {
        	TransactionInput input = new TransactionInput(network, this, payload, cursor);
            inputs.add(input);
            cursor += input.getLength();
        }

		//交易输出数量
        long numOutputs = readVarInt();
        outputs = new ArrayList<TransactionOutput>((int) numOutputs);
        for (int i = 0; i < numOutputs; i++) {
        	TransactionOutput output = new TransactionOutput(network, this, payload, cursor);
        	output.setIndex(i);
            outputs.add(output);
            cursor += output.getLength();
        }
        time = readUint32();
        lockTime = readUint32();
        remark = readBytes((int)readVarInt());
        
        if(!isCompatible()) {
        	length = cursor - offset;
        }
	}
	
	/**
	 * 验证交易的合法性
	 */
	public void verify() throws VerificationException {
		
		byte[] content = baseSerialize();
		if(content.length > MAX_STANDARD_TX_SIZE) {
			throw new VerificationException("超过交易最大限制"+MAX_STANDARD_TX_SIZE);
		}
		
		//备注不能超过100 byte
		if(remark != null && remark.length > Configure.MAX_REMARK_LEN) {
			throw new VerificationException("备注不能超过100字节");
		}
		
		if(type == Definition.TYPE_COINBASE) {
			return;
		}

		if(inputs != null && inputs.size() > 0) {
			//是否引用了不可用的输出
			for (int i = 0; i < inputs.size(); i++) {
				TransactionInput input = inputs.get(i);
				
				List<TransactionOutput> fromOutputs = input.getFroms();
				if(fromOutputs == null || fromOutputs.size() == 0) {
					throw new VerificationException("交易缺少输入");
				}
				if(fromOutputs.size() > 20000) {
					throw new VerificationException("交易输入引用最多20000个");
				}

				//交易输入引用必须存在
				//且交易不能有多个相同的引用
				for (TransactionOutput transactionOutput : fromOutputs) {
					if(transactionOutput.getParent() == null) {
						throw new VerificationException("交易输入缺少对父交易的引用");
					}
				}
			}
		}
		
		//交易输出最多200个
		if(outputs.size() > 200) {
			throw new VerificationException("交易输出最多200个");
		}
	}

	public Sha256Hash hashForSignature(int index, byte[] redeemScript, byte sigHashType) {
		try {
            Transaction tx = this.network.getDefaultSerializer().makeTransaction(this.baseSerialize());
            //清空输入脚本
            for (int i = 0; i < tx.inputs.size(); i++) {
                tx.getInputs().get(i).clearScriptBytes();
            }
            //清除上次交易脚本里的操作码
            redeemScript = Script.removeAllInstancesOfOp(redeemScript, ScriptOpCodes.OP_CODESEPARATOR);

            Input input = tx.inputs.get(index);
            input.setScriptBytes(redeemScript);

            if ((sigHashType & 0x1f) == SigHash.NONE.value) {
            	//TODO
            	
            }
            
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(tx.length == UNKNOWN_LENGTH ? 256 : tx.length + 4);
            tx.serializeToStream(bos);
            //把hash的类型加到最后
            Utils.uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
            //计算交易内容的sha256 hash
            Sha256Hash hash = Sha256Hash.twiceOf(bos.toByteArray());
            bos.close();
            return hash;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
	}
	
	public Sha256Hash hashForSignature(int inputIndex, byte[] redeemScript, SigHash type) {
		byte sigHashType = (byte) TransactionSignature.calcSigHashValue(type);
		return hashForSignature(inputIndex, redeemScript, sigHashType);
	}
	
	/**
	 * 签名交易
	 * @param inputIndex
	 * @param key			密匙
	 * @param redeemScript	上次交易的赎回脚本
	 * @param hashType		hash类型
	 * @return TransactionSignature
	 */
	public TransactionSignature calculateSignature(int inputIndex, ECKey key, byte[] redeemScript, SigHash hashType) {
		Sha256Hash hash = hashForSignature(inputIndex, redeemScript, hashType);
		return new TransactionSignature(key.sign(hash), hashType);
	}
	
	/**
	 * 添加输入
	 * @param output
	 */
	public TransactionInput addInput(TransactionOutput output) {
		return addInput(new TransactionInput(output));
	}

	/**
	 * 添加输入
	 * @param input
	 */
    public TransactionInput addInput(TransactionInput input) {
        input.setParent(this);
        inputs.add(input);
        return input;
    }
    
    /**
     * 添加输出
     * @param output
     * @return TransactionOutput
     */
	public TransactionOutput addOutput(TransactionOutput output) {
		output.setParent(this);
		output.setIndex(outputs.size());
		outputs.add(output);
        return output;
	}
	
	/**
	 * 输出到指定地址
	 * @param value
	 * @param address
	 * @return TransactionOutput
	 */
	public TransactionOutput addOutput(Coin value, Address address) {
        return addOutput(new TransactionOutput(this, value, address));
    }
	
	/**
	 * 输出到指定地址
	 * @param value
	 * @param address
	 * @return TransactionOutput
	 */
	public TransactionOutput addOutput(Coin value, long lockTime, Address address) {
		return addOutput(new TransactionOutput(this, value, lockTime, address));
	}

	/**
	 * 输出到pubkey
	 * @param value
	 * @param pubkey
	 * @return TransactionOutput
	 */
	public TransactionOutput addOutput(Coin value, ECKey pubkey) {
        return addOutput(new TransactionOutput(this, value, pubkey));
    }

	/**
	 * 输出到脚本
	 * @param value
	 * @param script
	 * @return TransactionOutput
	 */
    public TransactionOutput addOutput(Coin value, Script script) {
        return addOutput(new TransactionOutput(this, value, 0l, script.getProgram()));
    }
    
    /**
     * 是否有代币相关的交易，比如转账时单纯的代币交易，也可能包含很多业务流程有使用到代币的情况，比如验证奖励
     * @return boolean
     */
	public boolean isPaymentTransaction() {
		return Definition.isPaymentTransaction(type);
	}

	/**
	 * 获取交易的交易费
	 * @return Coin
	 */
	public Coin getFee() {
		return null;
	}

    @Override
    public String toString() {
    	return "tx: " +getHash() + " inputSize:" + (inputs == null ? 0:inputs.size()) + " outputSize:" + (outputs == null ? 0:outputs.size());
    }
    
    @Override
    public boolean equals(Object obj) {
    	if(obj == null) {
    		return false;
    	}
    	if(!(obj instanceof Transaction)) {
    		return false;
    	}
    	Transaction other = (Transaction) obj;
    	if(other.getHash() == null) {
    		return false;
    	}
    	return getHash().equals(other.getHash());
    }
    
    public TransactionInput getInput(int index) {
        return inputs.get(index);
    }

    public TransactionOutput getOutput(int index) {
        return outputs.get(index);
    }
    
    public List<TransactionInput> getInputs() {
		return inputs;
	}
    
    public List<TransactionOutput> getOutputs() {
		return outputs;
	}

    public long getLockTime() {
		return lockTime;
	}
    public void setLockTime(long lockTime) {
		this.lockTime = lockTime;
	}
    public long getTime() {
		return time;
	}
    public void setTime(long time) {
		this.time = time;
	}

	public Sha256Hash getHash() {
		if (hash == null) {
            hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(unsafeBitcoinSerialize()));
        }
		return hash;
	}
	public Sha256Hash getHashNoCache() {
		return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(unsafeBitcoinSerialize()));
	}

	public void setHash(Sha256Hash hash) {
		this.hash = hash;
	}
	public void setVersion(long version) {
		this.version = version;
	}
	public long getVersion() {
		return version;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}
	
	public void setRemark(byte[] remark) {
		this.remark = remark;
	}
	
	public byte[] getRemark() {
		return remark;
	}
}
