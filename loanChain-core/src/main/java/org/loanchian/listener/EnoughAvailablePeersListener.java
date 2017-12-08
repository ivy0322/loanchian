package org.loanchian.listener;

import org.loanchian.core.Peer;

import java.util.List;

/**
 * 已连接的对等体数量达到一定值的监听
 * @author ln
 *
 */
public interface EnoughAvailablePeersListener {

	void callback(List<Peer> peers);
}
