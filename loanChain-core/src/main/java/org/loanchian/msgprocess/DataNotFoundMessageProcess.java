package org.loanchian.msgprocess;

import org.loanchian.core.DataSynchronizeHandler;
import org.loanchian.core.Peer;
import org.loanchian.message.DataNotFoundMessage;
import org.loanchian.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 数据没有找到处理
 * @author ln
 *
 */
@Service
public class DataNotFoundMessageProcess implements MessageProcess {

	private static final Logger log = LoggerFactory.getLogger(DataNotFoundMessageProcess.class);
	
	@Autowired
	private DataSynchronizeHandler dataSynchronizeHandler;
	
	@Override
	public MessageProcessResult process(Message message, Peer peer) {
		
		if(log.isDebugEnabled()) {
			log.debug("receive DataNotFoundMessage message: {}", message);
		}
		
		DataNotFoundMessage dataNotFoundMessage = (DataNotFoundMessage) message;
		
		//信息没有找到，有可能是同步区块时，没有更多消息，交给下载器去判断处理
		dataSynchronizeHandler.dataNotFoundCheck(dataNotFoundMessage.getHash());
		
		return new MessageProcessResult(dataNotFoundMessage.getHash(), false);
	}
}
