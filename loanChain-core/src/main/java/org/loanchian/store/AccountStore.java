package org.loanchian.store;

import org.loanchian.account.AccountBody;
import org.loanchian.account.Address;
import org.loanchian.core.VarInt;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;
import org.loanchian.utils.Utils;
import org.spongycastle.util.Arrays;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 账户信息存储
 * @author ln
 *
 */
public class AccountStore extends Store {

	public enum AccountType {
		SYSTEM,	//系统普通账户
		CERT,	//认证账户
	}
	
	//账户类型
	private int type;
	private byte[] hash160;
	//账户状态
	private byte status;
	private int level;
	private byte[] supervisor;
	//别名
	private byte[] alias;
	private byte[][] pubkeys;
	private long balance;
	private long lastModifyTime;
	private long createTime;
	private long cert;	//信用值
	private Sha256Hash infoTxid;
	private AccountBody accountBody;

	public AccountStore(NetworkParams network) {
		super(network);
	}
	
	public AccountStore(NetworkParams network, byte[] payload) {
		super(network, payload, 0);
	}
	
	public AccountStore(NetworkParams network, byte[] payload, int offset) {
		super(network, payload, offset);
	}

	@Override
	protected void serializeToStream(OutputStream stream) throws IOException {
		stream.write(type);
		stream.write(hash160);
		stream.write(status);
		stream.write(level);
		if(supervisor == null){
			stream.write(new VarInt(0).encode());
		}else {
			stream.write(new VarInt(supervisor.length).encode());
			stream.write(supervisor);
		}

		if(alias == null) {
			stream.write(new VarInt(0).encode());
		} else {
			stream.write(new VarInt(alias.length).encode());
			stream.write(alias);
		}
		
		if(type == network.getSystemAccountVersion()) {
			stream.write(new VarInt(pubkeys[0].length).encode());
			stream.write(pubkeys[0]);
		} else {
			for (byte[] pubkey : pubkeys) {
				stream.write(new VarInt(pubkey.length).encode());
				stream.write(pubkey);
			}
			stream.write(infoTxid.getReversedBytes());
		}
		
		Utils.int64ToByteStreamLE(balance, stream);
		Utils.uint32ToByteStreamLE(lastModifyTime, stream);
		Utils.uint32ToByteStreamLE(createTime, stream);
		Utils.int64ToByteStreamLE(cert, stream);

		stream.write(accountBody.serialize());
	}
	
	@Override
	protected void parse() throws ProtocolException {
		type = readBytes(1)[0] & 0xff;
		hash160 = readBytes(Address.LENGTH);
		status = readBytes(1)[0];
		level = readBytes(1)[0] & 0xff;
		supervisor = readBytes((int)readVarInt());

		int aliasLength = (int) readVarInt();
		if(aliasLength > 0) {
			alias = readBytes(aliasLength);
		}
		
		if(type == network.getSystemAccountVersion()) {
			pubkeys = new byte[][] {readBytes((int) readVarInt())};
		} else {
			pubkeys = new byte[][] {
				readBytes((int) readVarInt()),
				readBytes((int) readVarInt()),
				readBytes((int) readVarInt()),
				//readBytes((int) readVarInt())
				};
			infoTxid = readHash();
		}
		balance = readInt64();
		lastModifyTime = readUint32();
		createTime = readUint32();
		cert = readInt64();

		
		if(cursor < payload.length) {
			try {
				accountBody = new AccountBody(Arrays.copyOfRange(payload, cursor, payload.length));
			}catch (Exception e){
				accountBody = AccountBody.empty();
			}
		} else {
			accountBody = AccountBody.empty();
		}
		
		length = cursor + accountBody.serialize().length - offset;
	}

	public String getAddress() {
		return new Address(network, type, hash160).getBase58();
	}
	
	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}

	public byte[] getHash160() {
		return hash160;
	}

	public void setHash160(byte[] hash160) {
		this.hash160 = hash160;
	}

	public byte[][] getPubkeys() {
		return pubkeys;
	}

	public void setPubkeys(byte[][] pubkeys) {
		this.pubkeys = pubkeys;
	}

	public long getBalance() {
		return balance;
	}

	public void setBalance(long balance) {
		this.balance = balance;
	}

	public long getLastModifyTime() {
		return lastModifyTime;
	}

	public void setLastModifyTime(long lastModifyTime) {
		this.lastModifyTime = lastModifyTime;
	}

	public long getCreateTime() {
		return createTime;
	}

	public void setCreateTime(long createTime) {
		this.createTime = createTime;
	}

	public long getCert() {
		return cert;
	}

	public void setCert(long cert) {
		this.cert = cert;
	}

	public void setInfoTxid(Sha256Hash infoTxid) {
		this.infoTxid = infoTxid;
	}
	
	public Sha256Hash getInfoTxid() {
		return infoTxid;
	}

	public AccountBody getAccountBody() {
		return accountBody;
	}

	public void setAccountBody(AccountBody accountBody) {
		this.accountBody = accountBody;
	}
	
	public void setAlias(byte[] alias) {
		this.alias = alias;
	}
	
	public byte[] getAlias() {
		return alias;
	}

	public byte getStatus(){
		return status;
	}

	public void setStatus(byte status){
		this.status = status;
	}

	public int getLevel(){return  this.level;}

	public void setLevel(int level){this.level = level;}

	public byte[] getSupervisor(){return this.supervisor;}

	public void setSupervisor(byte[] supervisor){this.supervisor = supervisor;}
}
