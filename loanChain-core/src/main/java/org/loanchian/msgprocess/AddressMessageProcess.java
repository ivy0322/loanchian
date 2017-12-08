package org.loanchian.msgprocess;

import org.loanchian.core.Peer;
import org.loanchian.core.PeerAddress;
import org.loanchian.kits.PeerKit;
import org.loanchian.message.AddressMessage;
import org.loanchian.message.GetAddressMessage;
import org.loanchian.message.Message;
import org.loanchian.network.NetworkParams;
import org.loanchian.network.PeerDiscovery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * p2p网络地址消息处理
 * @author ln
 *
 */
@Service
public class AddressMessageProcess implements MessageProcess {

	private static final Logger log = LoggerFactory.getLogger(AddressMessageProcess.class);

	@Autowired
	private NetworkParams network;
	@Autowired
	private PeerKit peerKit;
	@Autowired
	private PeerDiscovery peerDiscovery;
	
	@Override
	public MessageProcessResult process(Message message, Peer peer) {
		
		if(log.isDebugEnabled()) {
			log.debug("receive addr or getaddr message : {}", message);
		}
		
		MessageProcessResult result = null;
		
		if(message instanceof AddressMessage) {
			AddressMessage addressMessage = (AddressMessage)message;
			
			List<PeerAddress> list = addressMessage.getAddresses();
			if(list.size() > 1) {
				peerDiscovery.addBath(addressMessage.getAddresses());
			} else {
				//单个时，验证之后加入，并且转播，如果这里验证，会对目标节点造成不小的并发压力，所以不验证了，直接转播 ，交由各节点异步验证
//				boolean success = peerKit.verifyPeer(list.get(0));
				//验证不通过，就被丢弃
//				if(success) {
					boolean success = peerDiscovery.add(list.get(0), false);
					if(success) {
						peerKit.broadcastMessage(addressMessage);
					}
//				}
			}
		} else if(message instanceof GetAddressMessage){

			AddressMessage replyMessage = new AddressMessage(network);
			
			List<PeerAddress> peerAddresses = peerDiscovery.getAvailablePeerAddress();
			for (PeerAddress peerAddress : peerAddresses) {
				replyMessage.addAddress(peerAddress);
			}
			
			result = new MessageProcessResult(null, true, replyMessage);
		}
		return result;
	}
}
