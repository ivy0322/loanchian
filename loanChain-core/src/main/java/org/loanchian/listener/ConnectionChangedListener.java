package org.loanchian.listener;

import org.loanchian.core.Peer;

import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 连接节点状态发生变化监听（连接状态，是指连接新节点或者老节点断开连接）
 * @author ln
 *
 */
public interface ConnectionChangedListener {

	void onChanged(int inCount, int outCount, int superCount, CopyOnWriteArrayList<Peer> inPeers, CopyOnWriteArrayList<Peer> outPeers, CopyOnWriteArrayList<Peer> superPeers);
}
