package org.loanchian.transaction.business;

import org.loanchian.core.Definition;
import org.loanchian.core.VarInt;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.network.NetworkParams;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 注册别名
 * @author ln
 *
 */
public class RegAliasTransaction extends CommonlyTransaction {

	private byte[] alias;
	
	public RegAliasTransaction(NetworkParams network) {
		super(network);
		type = Definition.TYPE_REG_ALIAS;
	}
	
	public RegAliasTransaction(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
		this(params, payloadBytes, 0);
    }
	
	public RegAliasTransaction(NetworkParams params, byte[] payloadBytes, int offset) throws ProtocolException {
		super(params, payloadBytes, offset);
	}
	
	@Override
	public void verify() throws VerificationException {
		super.verify();
		//别名不能超过30 字节
		if(alias == null) {
			throw new VerificationException("别名不能为空");
		}
		if(alias.length > 30) {
			throw new VerificationException("别名不能超过30字节");
		}
	}
	
	@Override
	protected void serializeBodyToStream(OutputStream stream) throws IOException {
		stream.write(new VarInt(alias.length).encode());
		stream.write(alias);
	}
	
	@Override
	protected void parseBody() throws ProtocolException {
		alias = readBytes((int)readVarInt());
	}

	public byte[] getAlias() {
		return alias;
	}

	public void setAlias(byte[] alias) {
		this.alias = alias;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RegAliasTransaction [alias=");
		builder.append(new String(alias));
		builder.append("]");
		return builder.toString();
	}
}
