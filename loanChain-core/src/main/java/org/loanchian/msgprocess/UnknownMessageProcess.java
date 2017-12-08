package org.loanchian.msgprocess;

import org.loanchian.core.Peer;
import org.loanchian.message.Message;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class UnknownMessageProcess implements MessageProcess {

	private static final org.slf4j.Logger log = LoggerFactory.getLogger(UnknownMessageProcess.class);
	
	@Override
	public MessageProcessResult process(Message message, Peer peer) {
		log.warn("receive unknown message {}", message);
		return null;
	}
}
