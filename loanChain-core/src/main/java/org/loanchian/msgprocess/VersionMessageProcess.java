package org.loanchian.msgprocess;

import org.loanchian.core.Peer;
import org.loanchian.core.TimeService;
import org.loanchian.core.exception.ProtocolException;
import org.loanchian.message.BlockHeader;
import org.loanchian.message.Message;
import org.loanchian.message.VerackMessage;
import org.loanchian.message.VersionMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Locale;

/**
 * 收到一个版本消息，必须回应一个包含自己版本的信息
 * @author ln
 *
 */
@Service
public class VersionMessageProcess implements MessageProcess {

	private static final Logger log = LoggerFactory.getLogger(VersionMessageProcess.class);
	
	@Override
	public MessageProcessResult process(Message message, Peer peer) {
		VersionMessage versionMessage = (VersionMessage) message;
		
		if (peer.getPeerVersionMessage() != null)
            throw new ProtocolException("Got two version messages from peer");
		
		peer.setPeerVersionMessage(versionMessage);
		
        // Switch to the new protocol version.
        long peerTime = versionMessage.getTime();
        log.info("Got host={}, version={}, subVer='{}', services=0x{}, time={}, blocks={}, bestBlockHash={}",
        		peer.getAddress(),
                versionMessage.getClientVersion(),
                versionMessage.getSubVer(),
                versionMessage.getLocalServices(),
                String.format(Locale.getDefault(), "%tF %tT", peerTime, peerTime),
                versionMessage.getBestHeight(),
                versionMessage.getBestBlockHash());
        
        if (versionMessage.getBestHeight() < 0) {
            // In this case, it's a protocol violation.
            throw new ProtocolException("Peer reports invalid best height: " + versionMessage.getBestHeight());
        }
        
        try {
        	//响应
        	peer.sendMessage(new VerackMessage(peer.getNetwork(), TimeService.currentTimeMillis(), versionMessage.getNonce()));
        	
        	//回应自己的版本信息
        	if(!peer.isHandshake()) {
	            BlockHeader bestBlockHeader = peer.getNetwork().getBestBlockHeader();
	            
				VersionMessage replyMessage = new VersionMessage(peer.getNetwork(), bestBlockHeader.getHeight(), bestBlockHeader.getHash(), peer.getPeerAddress());
				peer.sendMessage(replyMessage);
				peer.setSendVersionMessageTime(System.currentTimeMillis());
        	}
        } catch (Exception e) {
        	log.error("回应版本信息出错", e);
        	peer.close();
		}
		return null;
	}
}
