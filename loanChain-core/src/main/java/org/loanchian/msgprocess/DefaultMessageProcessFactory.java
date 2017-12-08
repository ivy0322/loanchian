package org.loanchian.msgprocess;

import org.loanchian.SpringContextUtils;
import org.loanchian.core.Definition;
import org.loanchian.message.Message;

/**
 * 消息处理器工厂
 * @author ln
 *
 */
public class DefaultMessageProcessFactory implements MessageProcessFactory {

	private static final MessageProcessFactory INSTANCE = new DefaultMessageProcessFactory();
	
	private DefaultMessageProcessFactory() {
	}
	
	public static MessageProcessFactory getInstance() {
		return INSTANCE;
	}
	
	@Override
	public MessageProcess getFactory(Message message) {
		
		if(message == null) {
			return SpringContextUtils.getBean(UnknownMessageProcess.class);
		}
		String processId = Definition.PROCESS_FACTORYS.get(message.getClass());
		if(processId == null) {
			return SpringContextUtils.getBean(UnknownMessageProcess.class);
		}
		MessageProcess messageProcess = SpringContextUtils.getBean(processId);
		if(messageProcess == null) {
			messageProcess = SpringContextUtils.getBean(UnknownMessageProcess.class);
		}
		return messageProcess;
	}
}
