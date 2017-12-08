package org.loanchian.message;

import org.loanchian.core.exception.ProtocolException;
import org.loanchian.network.NetworkParams;

import java.io.IOException;
import java.io.OutputStream;

/**
 * 空消息的定义
 * @author ln
 *
 */
public abstract class EmptyMessage extends Message {

    public EmptyMessage() {
        length = 0;
    }

    public EmptyMessage(NetworkParams params) {
        super(params);
        length = 0;
    }

    public EmptyMessage(NetworkParams params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        length = 0;
    }

    @Override
    protected final void serializeToStream(OutputStream stream) throws IOException {
    }

    @Override
    protected void parse() throws ProtocolException {
    }

    @Override
    public byte[] baseSerialize() {
        return new byte[0];
    }
}
