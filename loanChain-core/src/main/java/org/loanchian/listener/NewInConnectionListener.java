package org.loanchian.listener;

import org.loanchian.core.Peer;

import java.net.InetSocketAddress;

/**
 * 新连接监听器，用于询问是否允许连接
 * @author ln
 *
 */
public interface NewInConnectionListener {

	boolean allowConnection(InetSocketAddress inetSocketAddress);
	
	void connectionOpened(Peer peer);
	
	void connectionClosed(Peer peer);
}
