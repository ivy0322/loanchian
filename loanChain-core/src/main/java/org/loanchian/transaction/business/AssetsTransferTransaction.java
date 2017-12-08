package org.loanchian.transaction.business;

import org.loanchian.core.Definition;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 资产交易
 */
public class AssetsTransferTransaction extends AssetsIssuedTransaction {

	public AssetsTransferTransaction(NetworkParams network) {
		super(network);
		type = Definition.TYPE_ASSETS_TRANSFER;
	}

	public AssetsTransferTransaction(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
		this(params, payloadBytes, 0);
	}

	public AssetsTransferTransaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
		super(params, payloadBytes, offset);
	}

	public AssetsTransferTransaction(NetworkParams params, Sha256Hash assetsHash, byte[] receiver, Long amount,byte[]remark) {
		super(params);
		this.amount = amount;
		this.assetsHash = assetsHash;
		this.receiver = receiver;
		this.remark = remark;
		type = Definition.TYPE_ASSETS_TRANSFER;
	}

	@Override
	public void verify() throws VerificationException {
		super.verify();
	}

	@Override
	protected void serializeBodyToStream(OutputStream stream) throws IOException {
		super.serializeBodyToStream(stream);
	}

	@Override
	protected void parseBody() throws ProtocolException {
		super.parseBody();
	}
}
