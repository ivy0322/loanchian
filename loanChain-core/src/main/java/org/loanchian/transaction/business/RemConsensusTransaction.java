package org.loanchian.transaction.business;

import org.loanchian.core.Definition;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.network.NetworkParams;
import org.loanchian.script.Script;
import org.loanchian.utils.Hex;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 退出共识交易
 * @author ln
 *
 */
public class RemConsensusTransaction extends BaseCommonlyTransaction {

	public RemConsensusTransaction(NetworkParams network) {
		super(network);
		this.type = Definition.TYPE_REM_CONSENSUS;
	}
	
	public RemConsensusTransaction(NetworkParams network, byte[] payloadBytes) {
		super(network, payloadBytes, 0);
	}
	
	public RemConsensusTransaction(NetworkParams network, byte[] payloadBytes, int offset) {
		super(network, payloadBytes, offset);
	}

	/**
	 * 验证交易的合法性
	 */
	public void verify() throws VerificationException {
		
		super.verify();
		
		if(type != Definition.TYPE_REM_CONSENSUS) {
			throw new VerificationException("交易类型错误");
		}
	}

	/**
	 * 验证交易脚本
	 */
	public void verifyScript() {
		//特殊的验证脚本
		super.verifyScript();
	}
	
	/**
	 * 序列化
	 */
	@Override
	protected void serializeBodyToStream(OutputStream stream) throws IOException {
		super.serializeBodyToStream(stream);
	}
	
	/**
	 * 反序列化
	 */
	@Override
	protected void parseBody() throws ProtocolException {
		super.parseBody();
	}
	
	public long getVersion() {
		return version;
	}

	public void setVersion(long version) {
		this.version = version;
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
	
	@Override
	public String toString() {
		return "RemConsensusTransaction [scriptBytes=" + Hex.encode(scriptBytes) + ", scriptSig=" + scriptSig + ", time=" + time + "]";
	}
	
}
