package org.loanchian.msgprocess;

import org.loanchian.consensus.ConsensusMeeting;
import org.loanchian.core.*;
import org.loanchian.filter.InventoryFilter;
import org.loanchian.kits.PeerKit;
import org.loanchian.message.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PreDestroy;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 向量清单消息处理器
 * @author ln
 *
 */
@Service
public class InventoryMessageProcess implements MessageProcess {

	private static final Logger log = LoggerFactory.getLogger(InventoryMessageProcess.class);
	
	//由于新区块的同步，需要线程阻塞，等待同步完成通知，避免重复下载，所以加入一个固定的线程池，异步执行，以免阻塞影响其它消息的接收执行
	private static final ExecutorService blockExecutorService = Executors.newSingleThreadExecutor();
	private static final ExecutorService newBlockExecutorService = Executors.newSingleThreadExecutor();
	private static final ExecutorService txExecutorService = Executors.newSingleThreadExecutor();

	//新区块同步锁
	private static Lock newBlockLocker = new ReentrantLock();
	//区块下载锁
	private static Lock blockLocker = new ReentrantLock();
	//交易下载锁
	private static Lock txLocker = new ReentrantLock();
	//其他消息下载锁
	private static Lock otherLocker = new ReentrantLock();

	@Autowired
	private PeerKit peerKit;
	@Autowired
	private InventoryFilter filter;
	@Autowired
	private DataSynchronizeHandler dataSynchronizeHandler;
	@Autowired
	private ConsensusMeeting consensusMeeting;

//	private Sha256Hash monitorBlockDownload;
	
	@Override
	public MessageProcessResult process(final Message message, final Peer peer) {
		
		if(log.isDebugEnabled()) {
			log.debug("receive inv message: {}", message);
		}
		
		InventoryMessage invMessage = (InventoryMessage) message;
		
		List<InventoryItem> invList = invMessage.getInvs();
		if(invList == null || invList.isEmpty()) {
			//通知下载完成
			peer.notifyDownloadComplete();
			return null;
		}
		
		//是否是区块下载消息
		boolean isBlockDownload = true;
		for (final InventoryItem inventoryItem : invList) {
			processInventoryItem(peer, inventoryItem);
			if(inventoryItem.getType() != InventoryItem.Type.Block) {
				isBlockDownload = false;
			}
		}
		if(isBlockDownload) {
			peer.setMonitorBlockDownload(invList.get(invList.size() - 1).getHash());
		}
		return null;
	}

	//处理明细
	private void processInventoryItem(final Peer peer, final InventoryItem inventoryItem) {
		//如果已经接收并处理过了，就跳过
		if(filter.contains(inventoryItem.getHash().getBytes()) && dataSynchronizeHandler.hasComplete()) {
			if(inventoryItem.getType() == InventoryItem.Type.NewBlock) {
				peer.addAndGetBestBlockHeight();
			}
			return;
		} else if(inventoryItem.getType() == InventoryItem.Type.NewBlock) {
			//新区块诞生
			newBlockExecutorService.submit(new Runnable() {
				@Override
				public void run() {
					newBlockInventory(inventoryItem, peer);
				}
			});
		} else if(inventoryItem.getType() == InventoryItem.Type.Block) {
			//区块下载
			blockExecutorService.submit(new Runnable() {
				@Override
				public void run() {
					blockInventory(inventoryItem, peer);
				}
			});
		} else if(inventoryItem.getType() == InventoryItem.Type.Transaction) {
			//交易的inv
			txExecutorService.submit(new Runnable() {
				@Override
				public void run() {
					txInventory(inventoryItem, peer);
				}
			});
		} else {
			//默认处理
			blockExecutorService.submit(new Runnable() {
				@Override
				public void run() {
					doProcessInventoryItem(peer, inventoryItem);
				}
			});
		}
	}

	/*
	 * 交易的inv
	 */
	protected void txInventory(InventoryItem inventoryItem, Peer peer) {
		txLocker.lock();
		try {
			if(filter.contains(inventoryItem.getHash().getBytes())) {
				return;
			}
			//当本地有广播结果等待时，代表该交易由我广播出去的，则不下载
			boolean needDown = false;
			
			BroadcastResult broadcastResult = BroadcastContext.get().get(inventoryItem.getHash());
			if(broadcastResult == null) {
				needDown = true;
			} else {
				broadcastResult.addReply(peer);
			}
			if(needDown) {
				//下载交易
				Future<GetDataResult> resultFuture = peer.sendGetDataMessage(new GetDatasMessage(peer.getNetwork(), inventoryItem));
				
				//获取下载结果，超时后切换
				GetDataResult result = resultFuture.get(6, TimeUnit.SECONDS);

				filter.insert(inventoryItem.getHash().getBytes());
				
				if(result.isSuccess()) {
					if(log.isDebugEnabled()) {
						log.debug("交易{}获取成功", inventoryItem.getHash());
					}
				}
			}
		} catch (Exception e) {
			log.error("交易inv消息处理失败 {}", inventoryItem, e);
		} finally {
			txLocker.unlock();
		}
	}

	/*
	 * 新区块同步
	 */
	private void newBlockInventory(final InventoryItem inventoryItem, Peer peer) {
		newBlockLocker.lock();
		try {
			consensusMeeting.waitMeeting();
			
			peer.addAndGetBestBlockHeight();
			if(!dataSynchronizeHandler.hasComplete() || filter.contains(inventoryItem.getHash().getBytes())) {
				if(!dataSynchronizeHandler.hasComplete()) {
					//没下载完的情况下，下载过程中也更新显示最新的区块高度
					if(peerKit.getBlockChangedListener() != null) {
						peerKit.getBlockChangedListener().onChanged(-1l, peer.getBestBlockHeight(), null, inventoryItem.getHash());
					}
				}
				return;
			}
			Future<GetDataResult> resultFuture = peer.sendGetDataMessage(new GetDatasMessage(peer.getNetwork(), inventoryItem));
			
			//获取下载结果，有超时时间
			GetDataResult result = resultFuture.get(6, TimeUnit.SECONDS);

			filter.insert(inventoryItem.getHash().getBytes());
			
			if(result.isSuccess()) {
				Block block = (Block) result.getData();
				
				if(log.isDebugEnabled()) {
					log.debug("新区块:高度 {} hash{} 同步成功", block.getHeight(), inventoryItem.getHash());
				}
				//区块变化监听器
				if(peerKit.getBlockChangedListener() != null) {
					peerKit.getBlockChangedListener().onChanged(-1l, block.getHeight(), null, inventoryItem.getHash());
				}
			}
			
		} catch (Exception e) {
			log.error("新区块inv消息处理失败 {}", inventoryItem, e);
		} finally {
			newBlockLocker.unlock();
		}
	}
	
	/*
	 * 区块下载
	 */
	private void blockInventory(final InventoryItem inventoryItem, Peer peer) {
		blockLocker.lock();
		try {
			if(filter.contains(inventoryItem.getHash().getBytes()) && dataSynchronizeHandler.hasComplete()) {
				return;
			}
//			Future<GetDataResult> resultFuture = peer.sendGetDataMessage(new GetDatasMessage(peer.getNetwork(), inventoryItem));
//			
//			//获取下载结果，有超时时间
//			GetDataResult result = resultFuture.get(30, TimeUnit.SECONDS);
//			
//			if(result.isSuccess()) {
//				Block block = (Block) result.getData();
//				
//				filter.insert(inventoryItem.getHash().getBytes());
//				if(log.isDebugEnabled()) {
//					log.debug("区块:高度 {} hash{} 同步成功", block.getHeight(), inventoryItem.getHash());
//				}
//				if(monitorBlockDownload != null && block.getHash().equals(monitorBlockDownload)) {
//					monitorBlockDownload = null;
//					//通知下载完成
//					peer.notifyDownloadComplete();
//				}
//			}
			
			peer.sendMessage(new GetDatasMessage(peer.getNetwork(), inventoryItem));
		} catch (Exception e) {
			log.error("区块下载inv消息处理失败 {}", inventoryItem, e);
		} finally {
			blockLocker.unlock();
		}
	}

	private void doProcessInventoryItem(Peer peer, InventoryItem inventoryItem) {
		try {
			otherLocker.lock();
			
			if(filter.contains(inventoryItem.getHash().getBytes())) {
				return;
			}
			
			Future<GetDataResult> resultFuture = peer.sendGetDataMessage(new GetDatasMessage(peer.getNetwork(), inventoryItem));
			//获取下载结果，有超时时间
			GetDataResult result = resultFuture.get(1, TimeUnit.SECONDS);
			if(result.isSuccess()) {
				filter.insert(inventoryItem.getHash().getBytes());
			}
		} catch (InterruptedException | ExecutionException | TimeoutException e) {
			e.printStackTrace();
		} finally {
			otherLocker.unlock();
		}
	}

	/**
	 * 程序关闭
	 */
	@PreDestroy
	public void shutdown() {
		newBlockExecutorService.shutdown();
		blockExecutorService.shutdown();
		txExecutorService.shutdown();
	}
}
