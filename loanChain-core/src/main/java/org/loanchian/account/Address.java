package org.loanchian.account;

import org.loanchian.core.Coin;
import org.loanchian.core.exception.AddressFormatException;
import org.loanchian.core.exception.VerificationException;
import org.loanchian.core.exception.WrongNetworkException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;
import org.loanchian.network.Networks;
import org.loanchian.utils.Base58;
import org.loanchian.utils.Hex;
import org.loanchian.utils.Utils;

import java.util.Arrays;

/**
 * 系统帐户的地址
 * @author ln
 *
 */
public class Address {
	
	//base58的长度
	public static final int HASH_LENGTH = 25;

	//address 的 RIPEMD160 长度
    public static final int LENGTH = 20;

    //所处网络环境
    protected transient NetworkParams network;

    //版本
    protected final int version;

    //内容
    protected byte[] bytes;

    //最新余额
    protected Coin balance;

    //等待中的余额
    protected Coin unconfirmedBalance;
    
    /**
     * 根据hash160创建
     * @param network
     * @param hash160
     */
    public Address(NetworkParams network, byte[] hash160) {
    	this(network, network.getSystemAccountVersion(), hash160);
    }

    /**
     * 根据版本、hash160创建
     * @param network
     * @param hash160
     */
    public Address(NetworkParams network, int version, byte[] hash160) throws WrongNetworkException {
        Utils.checkNotNull(network);
        Utils.checkState(hash160.length == LENGTH, "地址的hash160不正确，必须是20位");
        if (!isAcceptableVersion(network, version))
            throw new WrongNetworkException(version, network.getAcceptableAddressCodes());
        this.version = version;
        this.network = network;
        this.bytes = hash160;
    }

	/**
     * 根据base58创建
     * @param network
     * @param address
     * @throws AddressFormatException
     * @throws WrongNetworkException
     */
    public Address(NetworkParams network, String address) throws AddressFormatException, WrongNetworkException{
    	byte[] versionAndDataBytes = Base58.decodeChecked(address);
        byte versionByte = versionAndDataBytes[0];
        version = versionByte & 0xFF;
        bytes = new byte[LENGTH];
        System.arraycopy(versionAndDataBytes, 1, bytes, 0, LENGTH);
        
        if (network != null) {
            if (!isAcceptableVersion(network, version)) {
                throw new WrongNetworkException(version, network.getAcceptableAddressCodes());
            }
            this.network = network;
        } else {
            NetworkParams paramsFound = null;
            for (NetworkParams p : Networks.get()) {
                if (isAcceptableVersion(p, version)) {
                    paramsFound = p;
                    break;
                }
            }
            if (paramsFound == null)
                throw new AddressFormatException("No network found for " + address);

            this.network = paramsFound;
        }
    }
    
    /**
     * 根据hash160创建地址
     * @param network
     * @param version
     * @return hash160
     */
    public static Address fromP2PKHash(NetworkParams network, int version, byte[] hash160) {
        try {
            return new Address(network, version, hash160);
        } catch (WrongNetworkException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
    
    /**
     * 根据hash内容创建地址
     * @param network
     * @param hashs
     * @return Address
     * @throws AddressFormatException
     */
    public static Address fromHashs(NetworkParams network, byte[] hashs) throws AddressFormatException {
    	
    	if(hashs == null || hashs.length != HASH_LENGTH) {
    		throw new AddressFormatException();
    	}
    	
    	int version = hashs[0] & 0XFF;
    	byte[] content = new byte[LENGTH];
        System.arraycopy(hashs, 1, content, 0, LENGTH);
    	
        byte[] sign = new byte[4];
    	System.arraycopy(hashs, 21, sign, 0, 4);
    	
    	Address address = new Address(network, version, content);
    	address.checkSign(sign);
    	
    	return address;
    }
    
    /**
     * 根据base58创建地址
     * @param network
     * @param address
     * @return Address
     * @throws AddressFormatException
     */
    public static Address fromBase58(NetworkParams network, String address) throws AddressFormatException {
    	return new Address(network, address);
    }

    public NetworkParams getParameters() {
        return network;
    }

    public static NetworkParams getParametersFromAddress(String address) throws AddressFormatException {
        try {
            return Address.fromBase58(null, address).getParameters();
        } catch (WrongNetworkException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
    
    /**
     * 获取包含版本和效验码的地址内容
     * @return byte[]
     */
    public byte[] getHash() {
    	//地址一共25字节
        byte[] versionAndHash160 = new byte[21];
        //加上版本号
        versionAndHash160[0] = (byte) version;
        //加上20字节的hash160
        System.arraycopy(bytes, 0, versionAndHash160, 1, bytes.length);
        //加上4位的效验码
        byte[] checkSin = getCheckSin(versionAndHash160);
        byte[] base58bytes = new byte[25];
        System.arraycopy(versionAndHash160, 0, base58bytes, 0, versionAndHash160.length);
        System.arraycopy(checkSin, 0, base58bytes, versionAndHash160.length, checkSin.length);
        return base58bytes;
    }
    
    /**
     * 获取包含版本和效验码的地址16进制编码
     * @return String
     */
    public String getHashAsHex() {
        return Hex.encode(getHash());
    }

    /**
     * 获取地址20字节的hash160
     * @return byte[]
     */
    public byte[] getHash160() {
    	return Utils.checkNotNull(bytes);
    }
    
    /**
     * 获取地址20字节的hash160 16进制编码
     * @return String
     */
    public String getHash160AsHex() {
        return Hex.encode(getHash160());
    }
    
    public String getBase58() {
    	return Base58.encode(getHash());
    }
    
    /**
     * 是否是认证账户地址
     * @return boolean
     */
    public boolean isCertAccount() {
    	return version == network.getCertAccountVersion();
    }

    /**
     * 检查连接的网络是否允许当前地址前缀
     * @param network
     * @param version
     * @return boolean
     */
    protected static boolean isAcceptableVersion(NetworkParams network, int version) {
        for (int v : network.getAcceptableAddressCodes()) {
            if (version == v) {
                return true;
            }
        }
        return false;
    }

    /**
     * This implementation narrows the return type to <code>Address</code>.
     */
    public Address clone() throws CloneNotSupportedException {
        return (Address) super.clone();
    }

    /*
     * 获取4位的效验码
     */
    protected byte[] getCheckSin(byte[] versionAndHash160) {
		byte[] checkSin = new byte[4];
		System.arraycopy(Sha256Hash.hashTwice(versionAndHash160), 0, checkSin, 0, 4);
		return checkSin;
	}
    
    protected void checkSign(byte[] sign) throws VerificationException {
    	//地址一共25字节
        byte[] versionAndHash160 = new byte[21];
        //加上版本号
        versionAndHash160[0] = (byte) version;
        //加上20字节的hash160
        System.arraycopy(bytes, 0, versionAndHash160, 1, bytes.length);
        
    	byte[] checkSin = new byte[4];
		System.arraycopy(Sha256Hash.hashTwice(versionAndHash160), 0, checkSin, 0, 4);
		
		if(!Arrays.equals(checkSin, sign)) {
			throw new VerificationException("地址校验失败");
		}
    }
    
    public int getVersion() {
		return version;
	}
    
    public Coin getBalance() {
		return balance;
	}

	public void setBalance(Coin balance) {
		this.balance = balance;
	}

	public Coin getUnconfirmedBalance() {
		return unconfirmedBalance;
	}

	public void setUnconfirmedBalance(Coin unconfirmedBalance) {
		this.unconfirmedBalance = unconfirmedBalance;
	}

	@Override
    public String toString() {
    	return "network="+network.getId()+", version="+version+", address="+getBase58();
    }
}
