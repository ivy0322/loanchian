package org.loanchian.transaction.business;

import org.loanchian.account.AccountBody;
import org.loanchian.core.Definition;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.network.NetworkParams;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 认证账户信息修改
 * @author ln
 *
 */
public class CertAccountUpdateTransaction extends CertAccountRegisterTransaction {
	
	public CertAccountUpdateTransaction(NetworkParams network, byte[] hash160, byte[][] mgPubkeys, byte[][] trPubkeys, AccountBody body,byte[] superhash160,int superlevel) {
		super(network, hash160, mgPubkeys, trPubkeys, body,superhash160,superlevel-1);
		this.setType(Definition.TYPE_CERT_ACCOUNT_UPDATE);
	}
	
	public CertAccountUpdateTransaction(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
		this(params, payloadBytes, 0);
    }
	
	public CertAccountUpdateTransaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
		super(params, payloadBytes, offset);
	}
	
	/**
	 * 反序列化交易
	 */
	protected void parseBody() {
		super.parseBody();
	}
	
	@Override
	protected void serializeBodyToStream(OutputStream stream) throws IOException {
		super.serializeBodyToStream(stream);
	}
	
	/**
	 * 验证交易的合法性
	 */
	@Override
	public void verify() throws VerificationException {
		super.verify();
	}
}
