package org.loanchian.msgprocess;

import org.loanchian.crypto.Sha256Hash;
import org.loanchian.message.Message;

/**
 * 消息处理结果
 * @author ln
 *
 */
public class MessageProcessResult {

	//消息的hash值
	private Sha256Hash hash;
	//消息是否处理成功
	private final boolean success;
	//错误代码
	private int errorCode;
	//是否回复消息，当不为空时回复
	private Message replyMessage;
	
	public MessageProcessResult(boolean success) {
		this(null, success, null);
	}
	
	public MessageProcessResult(Sha256Hash hash, boolean success) {
		this(hash, success, null);
	}

	public MessageProcessResult(Sha256Hash hash, boolean success, Message replyMessage) {
		this.hash = hash;
		this.success = success;
		this.replyMessage = replyMessage;
	}
	
	public boolean isSuccess() {
		return success;
	}
	public Message getReplyMessage() {
		return replyMessage;
	}
	public Sha256Hash getHash() {
		return hash;
	}

	public int getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(int errorCode) {
		this.errorCode = errorCode;
	}
}
