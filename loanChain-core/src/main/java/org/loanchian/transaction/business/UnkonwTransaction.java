package org.loanchian.transaction.business;

import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.network.NetworkParams;
import org.loanchian.utils.Utils;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * 未知的交易，用于老版本兼容新协议
 * @author ln
 *
 */
public class UnkonwTransaction extends CommonlyTransaction {

	private byte[] content;
	
	public UnkonwTransaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
		super(params);
		long bodyLength = Utils.readUint32(payloadBytes, 1);
        this.content = Arrays.copyOfRange(payloadBytes, 0, (int)bodyLength);
        length = content.length;
	}

	@Override
	public void verify() throws VerificationException {
	}
	
	@Override
	public void verifyScript() {
	}
	
	@Override
	protected void parse() throws ProtocolException {
	}
	
	@Override
	protected void serializeToStream(OutputStream stream) throws IOException {
		stream.write(content);
	}
}
