package org.loanchian.message;


import org.loanchian.core.Definition;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.network.NetworkParams;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.business.UnkonwTransaction;
import org.loanchian.utils.Hex;
import org.loanchian.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class DefaultMessageSerializer extends MessageSerializer {

	private static final Logger log = LoggerFactory.getLogger(DefaultMessageSerializer.class);
	
	private final NetworkParams network;
	
	public DefaultMessageSerializer(NetworkParams network) {
		this.network = network;
	}

	@Override
    public void serialize(String command, byte[] message, OutputStream out) throws IOException {
        byte[] header = new byte[4 + COMMAND_LEN + 4 + 4 /* checksum */];
        Utils.uint32ToByteArrayBE(network.getPacketMagic(), header, 0);

        // The header array is initialized to zero by Java so we don't have to worry about
        // NULL terminating the string here.
        for (int i = 0; i < command.length() && i < COMMAND_LEN; i++) {
            header[4 + i] = (byte) (command.codePointAt(i) & 0xFF);
        }

        Utils.uint32ToByteArrayLE(message.length, header, 4 + COMMAND_LEN);

        byte[] hash = Sha256Hash.hashTwice(message);
        System.arraycopy(hash, 0, header, 4 + COMMAND_LEN + 4, 4);
        out.write(header);
        out.write(message);

        if (log.isDebugEnabled())
            log.debug("Sending {} message: {}", command, Hex.encode(header) + Hex.encode(message));
    }
	
	@Override
    public void serialize(Message message, OutputStream out) throws IOException {
        String command = Definition.MESSAGE_COMMANDS.get(message.getClass());
        if (command == null) {
            throw new Error("DefaultSerializer doesn't currently know how to serialize " + message.getClass());
        }
        serialize(command, message.baseSerialize(), out);
    }
	
	@Override
	public Message deserialize(ByteBuffer in) throws ProtocolException, IOException, UnsupportedOperationException {
		// protocol message has the following format.
        //
        //   - 4 byte magic number: 0xfabfb5da for the testnet or
        //                          0xf9beb4d9 for production
        //   - 12 byte command in ASCII
        //   - 4 byte payload size
        //   - 4 byte checksum
        //   - Payload data
        //
        // The checksum is the first 4 bytes of a SHA256 hash of the message payload. It isn't
        // present for all messages, notably, the first one on a connection.
        //
        // Bitcoin Core ignores garbage before the magic header bytes. We have to do the same because
        // sometimes it sends us stuff that isn't part of any message.
        seekPastMagicBytes(in);
        MessagePacketHeader header = new MessagePacketHeader(in);
        // Now try to read the whole message.
        return deserializePayload(header, in);
	}

	@Override
	public MessagePacketHeader deserializeHeader(ByteBuffer in) throws ProtocolException, IOException, UnsupportedOperationException {
		return new MessagePacketHeader(in);
	}

	@Override
	public Message deserializePayload(MessagePacketHeader header, ByteBuffer in)
			throws ProtocolException, BufferUnderflowException, UnsupportedOperationException {
		byte[] payloadBytes = new byte[header.size];
        in.get(payloadBytes, 0, header.size);

        // Verify the checksum.
        byte[] hash;
        hash = Sha256Hash.hashTwice(payloadBytes);
        if (header.checksum[0] != hash[0] || header.checksum[1] != hash[1] ||
                header.checksum[2] != hash[2] || header.checksum[3] != hash[3]) {
            throw new ProtocolException("Checksum failed to verify, actual " +
            		Hex.encode(hash) + " vs " + Hex.encode(header.checksum));
        }

        if (log.isDebugEnabled()) {
            log.debug("Received {} byte '{}' message: {}", header.size, header.command,
                    Hex.encode(payloadBytes));
        }

        try {
            return makeMessage(header.command, header.size, payloadBytes, hash, header.checksum);
        } catch (Exception e) {
            throw new ProtocolException("Error deserializing message " + Hex.encode(payloadBytes) + "\n", e);
        }
	}

	private Message makeMessage(String command, int size, byte[] payloadBytes, byte[] hash, byte[] checksum) {
		Message message = null;
		if(Definition.TRANSACTION_COMMANDS.contains(command)) {
			//根据交易类型来创建交易
			return makeTransaction(payloadBytes, 0);
		} else {
			//创建消息
	  		try {
	  			Class<?> clazz = Definition.COMMANDS_MESSAGE.get(command);
	  			if(clazz == null) {
		  			log.warn("反序列化消息通用方法出错, 未定义的消息 {}", command);
	  				return message;
	  			}
	  			Constructor<?> constructor = clazz.getDeclaredConstructor(NetworkParams.class, byte[].class);
	  			if(constructor == null) {
	  				constructor = clazz.getDeclaredConstructor(NetworkParams.class, String.class, byte[].class);
	  	        	log.warn("No support for deserializing message with name {}", command);
	  	        	message = (Message) constructor.newInstance(network, command, payloadBytes);
	  			} else {
	  				message = (Message) constructor.newInstance(network, payloadBytes);
	  			}
	  		} catch (Exception e) {
	  			log.error("反序列化消息通用方法出错：{}", e);
	  		}
		}
		return message;
	}

	@Override
	public void seekPastMagicBytes(ByteBuffer in) throws BufferUnderflowException {
		int magicCursor = 3;  // Which byte of the magic we're looking for currently.
        while (true) {
            byte b = in.get();
            // We're looking for a run of bytes that is the same as the packet magic but we want to ignore partial
            // magics that aren't complete. So we keep track of where we're up to with magicCursor.
            byte expectedByte = (byte)(0xFF & network.getPacketMagic() >>> (magicCursor * 8));
            if (b == expectedByte) {
                magicCursor--;
                if (magicCursor < 0) {
                    // We found the magic sequence.
                    return;
                } else {
                    // We still have further to go to find the next message.
                }
            } else {
                magicCursor = 3;
            }
        }
	}

	@Override
	public boolean isParseRetainMode() {
		return false;
	}

	/**
	 * 创建交易
	 */
	@Override
	public Transaction makeTransaction(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException {
        return this.makeTransaction(payloadBytes, null);
	}
	
	/**
	 * 创建交易
	 */
	@Override
	public Transaction makeTransaction(byte[] payloadBytes, Sha256Hash hash) throws ProtocolException, UnsupportedOperationException {
        Transaction tx = new Transaction(network, payloadBytes);
        if (hash != null)
            tx.setHash(hash);
        return tx;
	}
	
	/**
	 * 创建交易
	 */
	@Override
	public Transaction makeTransaction(byte[] payloadBytes, int offset) throws ProtocolException {
		//根据交易类型来创建交易
		int type = payloadBytes[offset] & 0XFF;
		
		try {
			Class<?> clazz = Definition.TRANSACTION_RELATION.get(type);
			if(clazz == null) {
				UnkonwTransaction unkonwTransaction = new UnkonwTransaction(network, payloadBytes, offset);
				if(log.isDebugEnabled()) {
					log.debug("没有配置的消息序列化");
				}
				return unkonwTransaction;
			}
			Constructor<?> constructor = clazz.getDeclaredConstructor(NetworkParams.class, byte[].class, int.class);
			
			return (Transaction) constructor.newInstance(network, payloadBytes, offset);
		} catch (Exception e) {
			log.error("序列化消息出错：{}", e);
			return null;
		}
	}

}
