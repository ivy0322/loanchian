package org.loanchian.msgprocess;

import org.loanchian.core.Peer;
import org.loanchian.message.Message;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class PongMessageProcess implements MessageProcess {

	private static final org.slf4j.Logger log = LoggerFactory.getLogger(PongMessageProcess.class);
	
	@Override
	public MessageProcessResult process(Message message, Peer peer) {
		
		if(log.isDebugEnabled()) {
			log.debug("{} {}", peer.getAddress(), message);
		}
		
		return new MessageProcessResult(null, true);
	}
}
