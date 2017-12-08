package org.loanchian.message;

import org.loanchian.core.exception.ProtocolException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 数据没有找到消息，用户回应GetDatasMessage
 * @author ln
 *
 */
public class DataNotFoundMessage extends Message {
	
	private Sha256Hash hash;
	
	public DataNotFoundMessage(NetworkParams network, Sha256Hash hash) {
        super();
        this.hash = hash;
    }
    
	public DataNotFoundMessage(NetworkParams network, byte[] payload) throws ProtocolException {
    	this(network, payload, 0);
    }
	
	public DataNotFoundMessage(NetworkParams network, byte[] payload, int offset) throws ProtocolException {
    	super(network, payload, offset);
    }
	
	@Override
	protected void parse() throws ProtocolException {
		hash = readHash();
		length = cursor - offset;
	}
	
	@Override
	protected void serializeToStream(OutputStream stream) throws IOException {
		stream.write(hash.getReversedBytes());
	}

	public Sha256Hash getHash() {
		return hash;
	}
	
	@Override
	public String toString() {
		return "DataNotFoundMessage [hash=" + hash + "]";
	}
}
