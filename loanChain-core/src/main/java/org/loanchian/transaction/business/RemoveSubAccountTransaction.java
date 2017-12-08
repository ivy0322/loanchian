package org.loanchian.transaction.business;

import org.loanchian.account.Address;
import org.loanchian.core.Definition;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 认证账户解除跟子账户的关联
 * @author ln
 *
 */
public class RemoveSubAccountTransaction extends CommonlyTransaction {

	//关联账户
	private byte[] relevanceHashs;
	//交易id
	private Sha256Hash txhash;
	
	public RemoveSubAccountTransaction(NetworkParams network, byte[] relevanceHashs, Sha256Hash txhash) {
		super(network);
		this.relevanceHashs = relevanceHashs;
		this.txhash = txhash;
		
		type = Definition.TYPE_REMOVE_SUBACCOUNT;
	}

	public RemoveSubAccountTransaction(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
		this(params, payloadBytes, 0);
    }
	
	public RemoveSubAccountTransaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
		super(params, payloadBytes, offset);
	}
	
	@Override
	public void verify() throws VerificationException {
		super.verify();
		
		if(relevanceHashs == null || relevanceHashs.length != Address.HASH_LENGTH) {
			throw new VerificationException("关联者错误");
		}
	}
	
	@Override
	protected void serializeBodyToStream(OutputStream stream) throws IOException {
		stream.write(relevanceHashs);
		stream.write(txhash.getReversedBytes());
	}
	
	@Override
	protected void parseBody() throws ProtocolException {
		relevanceHashs = readBytes(25);
		txhash = readHash();
	}

	public byte[] getRelevanceHashs() {
		return relevanceHashs;
	}

	public void setRelevanceHashs(byte[] relevanceHashs) {
		this.relevanceHashs = relevanceHashs;
	}

	public Sha256Hash getTxhash() {
		return txhash;
	}

	public void setTxhash(Sha256Hash txhash) {
		this.txhash = txhash;
	}
	
	public Address getAddress() {
		return Address.fromHashs(network, relevanceHashs);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RemoveSubAccountTransaction [relevanceHashs=");
		builder.append(Address.fromHashs(network, relevanceHashs).getBase58());
		builder.append(", txhash=");
		builder.append(txhash);
		builder.append("]");
		return builder.toString();
	}
}
