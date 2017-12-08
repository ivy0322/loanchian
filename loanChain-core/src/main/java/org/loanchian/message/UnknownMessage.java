package org.loanchian.message;

import org.loanchian.core.exception.ProtocolException;
import org.loanchian.network.NetworkParams;
import org.loanchian.utils.Hex;

/**
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class UnknownMessage extends EmptyMessage {

    private String name;

    public UnknownMessage(NetworkParams params, String name, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
        this.name = name;
    }

    @Override
    public String toString() {
        return "Unknown message [" + name + "]: " + (payload == null ? "" : Hex.encode(payload));
    }
}
