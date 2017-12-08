package org.loanchian.msgprocess;

import org.loanchian.message.Message;

/**
 * 消息处理
 * @author ln
 *
 */
public interface MessageProcessFactory {

	MessageProcess getFactory(Message message);
}
