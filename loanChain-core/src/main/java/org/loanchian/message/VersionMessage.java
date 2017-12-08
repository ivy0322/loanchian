package org.loanchian.message;

import org.loanchian.core.Definition;
import org.loanchian.core.PeerAddress;
import org.loanchian.core.TimeService;
import org.loanchian.core.VarInt;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;
import org.loanchian.utils.RandomUtil;
import org.loanchian.utils.Utils;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;


public class VersionMessage extends Message {

    /**
     * 哪个网络服务
     */
    private int localServices;
    
    /**
     * 协议版本
     */
    private int clientVersion;
    
    /**
     * 对等体的时间
     */
    private long time;
   
    /**
     * 我的网络地址
     */
    private PeerAddress myAddr;
    
    /**
     * 对等体的网络时间
     */
    private PeerAddress theirAddr;
    
    /**
     * 版本信息
     */
    private String subVer;
    
    /**
     * 对等体的区块数量
     */
    private long bestHeight;
    
    /**
     * 对等体最新区块的hash
     */
    private Sha256Hash bestBlockHash;
    
    /**
     * 随机数
     */
    private long nonce;
    
	public VersionMessage(NetworkParams params) throws ProtocolException {
        super(params);
    }
	
	public VersionMessage(NetworkParams params, byte[] payload) throws ProtocolException {
        super(params, payload, 0);
    }
	
	public VersionMessage(NetworkParams params, long bestHeight, Sha256Hash bestBlockHash, PeerAddress remoteAddress) throws UnknownHostException {
		this(params, bestHeight, bestBlockHash, null, remoteAddress);
	}
	
	public VersionMessage(NetworkParams params, long bestHeight, Sha256Hash bestBlockHash, PeerAddress myAddress, PeerAddress remoteAddress) throws UnknownHostException {
	    super(params);
        clientVersion = params.getProtocolVersionNum(NetworkParams.ProtocolVersion.CURRENT);
        localServices = params.getLocalServices();
        time = TimeService.currentTimeMillis();
        nonce = RandomUtil.randomLong();
        try {
        	if(myAddress == null) {
				final byte[] localhost = { 0, 0, 0, 0 };
				myAddr = new PeerAddress(InetAddress.getByAddress(localhost), params.getPort(), NetworkParams.ProtocolVersion.CURRENT.getVersion());
			} else {
        		myAddr = myAddress;
        	}
            if(remoteAddress == null) {
            	try {
            		theirAddr = new PeerAddress(InetAddress.getLocalHost(), params.getPort(), NetworkParams.ProtocolVersion.CURRENT.getVersion());
        		} catch (Exception e) {
        			final byte[] localhost = { 127, 0, 0, 1 };
        			theirAddr = new PeerAddress(InetAddress.getByAddress(localhost), params.getPort(), NetworkParams.ProtocolVersion.CURRENT.getVersion());
				}
            } else {
            	theirAddr = remoteAddress;
            }
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        subVer = Definition.LIBRARY_SUBVER;
        this.bestHeight = bestHeight;
        this.bestBlockHash = bestBlockHash;
	}
	
	@Override
	protected void parse() throws ProtocolException {
		localServices = readBytes(1)[0] & 0xFF;
		clientVersion = (int) readUint32();
        time = readInt64();
        
        myAddr = new PeerAddress(network, payload, cursor, 0);
        cursor += myAddr.getMessageSize();
        theirAddr = new PeerAddress(network, payload, cursor, 0);
        cursor += theirAddr.getMessageSize();
        
        subVer = readStr();
        bestHeight = readUint32();
        bestBlockHash = readHash();
        nonce = readInt64();
        length = cursor - offset;
	}
	
	@Override
    public void serializeToStream(OutputStream buf) throws IOException {
		buf.write(localServices);
        Utils.uint32ToByteStreamLE(clientVersion, buf);
        Utils.int64ToByteStreamLE(time, buf);
        try {
            // My address.
            myAddr.serializeToStream(buf);
            // Their address.
            theirAddr.serializeToStream(buf);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Can't happen.
        } catch (IOException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
        // Now comes subVer.
        byte[] subVerBytes = subVer.getBytes("UTF-8");
        buf.write(new VarInt(subVerBytes.length).encode());
        buf.write(subVerBytes);
        // Size of known block chain.
        Utils.uint32ToByteStreamLE(bestHeight, buf);
        buf.write(bestBlockHash.getReversedBytes());
        Utils.int64ToByteStreamLE(nonce, buf);
    }
	
	@Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("\n");
        stringBuilder.append("local services: ").append(localServices).append("\n");
        stringBuilder.append("client version: ").append(clientVersion).append("\n");
        stringBuilder.append("time:           ").append(time).append("\n");
        stringBuilder.append("my addr:        ").append(myAddr).append("\n");
        stringBuilder.append("their addr:     ").append(theirAddr).append("\n");
        stringBuilder.append("sub version:    ").append(subVer).append("\n");
        stringBuilder.append("best block height:    ").append(bestHeight).append("\n");
        stringBuilder.append("best block hash:    ").append(bestBlockHash).append("\n");
        stringBuilder.append("nonce:    ").append(nonce).append("\n");
        return stringBuilder.toString();
    }

	public int getLocalServices() {
		return localServices;
	}

	public void setLocalServices(int localServices) {
		this.localServices = localServices;
	}

	public int getClientVersion() {
		return clientVersion;
	}

	public void setClientVersion(int clientVersion) {
		this.clientVersion = clientVersion;
	}

	public long getTime() {
		return time;
	}

	public void setTime(long time) {
		this.time = time;
	}

	public PeerAddress getMyAddr() {
		return myAddr;
	}

	public void setMyAddr(PeerAddress myAddr) {
		this.myAddr = myAddr;
	}

	public PeerAddress getTheirAddr() {
		return theirAddr;
	}

	public void setTheirAddr(PeerAddress theirAddr) {
		this.theirAddr = theirAddr;
	}

	public String getSubVer() {
		return subVer;
	}

	public void setSubVer(String subVer) {
		this.subVer = subVer;
	}

	public long getBestHeight() {
		return bestHeight;
	}

	public void setBestHeight(long bestHeight) {
		this.bestHeight = bestHeight;
	}

	public Sha256Hash getBestBlockHash() {
		return bestBlockHash;
	}

	public void setBestBlockHash(Sha256Hash bestBlockHash) {
		this.bestBlockHash = bestBlockHash;
	}

	public long getNonce() {
		return nonce;
	}

	public void setNonce(long nonce) {
		this.nonce = nonce;
	}
}
