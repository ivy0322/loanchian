package org.loanchian.msgprocess;

import org.loanchian.core.Peer;
import org.loanchian.message.Message;

public interface MessageProcess {

	MessageProcessResult process(Message message, Peer peer);
}
