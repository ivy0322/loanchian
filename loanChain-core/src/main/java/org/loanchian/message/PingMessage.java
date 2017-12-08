package org.loanchian.message;

import org.loanchian.core.exception.ProtocolException;
import org.loanchian.network.NetworkParams;
import org.loanchian.utils.Utils;

import java.io.IOException;
import java.io.OutputStream;

/**
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class PingMessage extends Message {
    private long nonce;
    
    public PingMessage(NetworkParams params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }
    
    public PingMessage(long nonce) {
        this.nonce = nonce;
    }
    
    @Override
    public void serializeToStream(OutputStream stream) throws IOException {
        Utils.int64ToByteStreamLE(nonce, stream);
    }

    @Override
    protected void parse() throws ProtocolException {
        nonce = readInt64();
        length = 8;
    }
    
    public long getNonce() {
        return nonce;
    }

	@Override
	public String toString() {
		return "PingMessage [nonce=" + nonce + "]";
	}
}
