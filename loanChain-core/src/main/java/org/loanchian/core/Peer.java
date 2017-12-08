package org.loanchian.core;

import com.google.common.base.Preconditions;
import org.loanchian.SpringContextUtils;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.message.*;
import org.loanchian.msgprocess.DefaultMessageProcessFactory;
import org.loanchian.msgprocess.MessageProcess;
import org.loanchian.msgprocess.MessageProcessFactory;
import org.loanchian.msgprocess.MessageProcessResult;
import org.loanchian.network.NetworkParams;
import org.loanchian.transaction.Transaction;
import org.loanchian.utils.RandomUtil;
import org.slf4j.LoggerFactory;
import org.springframework.util.concurrent.SettableListenableFuture;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.NotYetConnectedException;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 节点（对等体）
 * @author ln
 *
 */
public class Peer extends PeerSocketHandler {
	
	private static final org.slf4j.Logger log = LoggerFactory.getLogger(Peer.class);
	
	//数据下载等待列表
	private static volatile Map<Sha256Hash, SettableListenableFuture<GetDataResult>> downDataFutures = new ConcurrentHashMap<Sha256Hash, SettableListenableFuture<GetDataResult>>();

	//ping futures
	private Map<Long, SettableListenableFuture<Boolean>> pingFutures = new ConcurrentHashMap<Long, SettableListenableFuture<Boolean>>();
	
	//异步顺序执行所有接收到的消息，以免有处理时间较长的线程阻塞，影响性能
	private ExecutorService executorService = Executors.newSingleThreadExecutor();
	
	//消息处理器工厂
	private static MessageProcessFactory messageProcessFactory = DefaultMessageProcessFactory.getInstance();

	//网络参数
	private NetworkParams network;

	//节点版本信息
	private VersionMessage peerVersionMessage;

	//节点最新高度
	private AtomicLong bestBlockHeight;

	//节点时间偏移
	private long timeOffset;

	//发送版本信息的时间，会根据回应计算该节点网络时间偏差
	private long sendVersionMessageTime;
	
	//监控下载完成的区块
	private Sha256Hash monitorBlockDownload;

	//设置可以监听的异步计算任务 - 异步下载任务
	private SettableListenableFuture<Boolean> downloadFuture;

	//区块同步开始的hash
	private Sha256Hash synchronizeDataStartHash;
	
	public Peer(NetworkParams network, InetSocketAddress address) {
		this(network, new PeerAddress(address));
	}
	
	public Peer(NetworkParams network, PeerAddress peerAddress) {
		super(network, peerAddress);
		this.network = network;
	}

	@Override
	protected void processMessage(final Message message) throws Exception {
		if(!handshake && !(message instanceof VersionMessage || message instanceof
				VerackMessage|| message instanceof PingMessage || message instanceof PongMessage)) {
    		log.warn("{} 节点还没有握手完成，不能通讯", peerAddress);
    		return;
    	}
		
		final MessageProcess messageProcess = messageProcessFactory.getFactory(message);
		if(messageProcess == null) {
			return;
		} else{
			executorService.submit(new Thread(){
				public void run() {
					//消息处理
					//当同步区块时，把消息交给同步器处理，其它情况则交给相应的消息处理器
					if(message instanceof Block && !(message instanceof NewBlockMessage)) {
						DataSynchronizeHandler synchronizeHandler = SpringContextUtils.getBean(DataSynchronizeHandler.class);
						synchronizeHandler.processData((Block) message);
					} else {
						MessageProcessResult result = messageProcess.process(message, Peer.this);
						processMessageResult(message, result);
					}
				};
			});
		}
	}
	
	/**
	 * 处理消息运行结果
	 * @param message 
	 * @param result
	 */
	protected void processMessageResult(Message message, MessageProcessResult result) {
		if(result == null) {
			return;
		}
		//处理完成之后的一些动作
		handleAfterProcess(message, result);
		//如果需要回应，那么这里发送回复消息
		if(result.getReplyMessage() != null) {
			try {
				sendMessage(result.getReplyMessage());
			} catch (NotYetConnectedException | IOException e) {
				e.printStackTrace();
			}
		}
		//是否成功
		if(!result.isSuccess()) {
		}
	}

	/*
	 * 接收到的消息处理成功，需要做一些额外的操作，在此执行
	 */
	private void handleAfterProcess(Message message, MessageProcessResult result) {
		Sha256Hash hash = null;
		//判断是否是区块或者交易下载完成
		if(message instanceof Block || message instanceof NewBlockMessage) {
			//区块下载完成
			hash = ((Block) message).getHash();
		} else if(message instanceof Transaction) {
			//交易下载完成
			hash = ((Transaction) message).getHash();
		} else if(message instanceof PongMessage) {
			//ping 的响应
			long nonce = ((PongMessage)message).getNonce();
			SettableListenableFuture<Boolean> futures = pingFutures.get(nonce);
			if(futures != null) {
				pingFutures.remove(nonce);
				futures.set(true);
			}
		} else if(message instanceof DataNotFoundMessage) {
			if(synchronizeDataStartHash != null && synchronizeDataStartHash.equals(result.getHash())) {
				//代表要下载的块对方没有
				if(downloadFuture != null) {
					downloadFuture.set(false);
				}
			}
		}
		if(hash == null) {
			hash = result.getHash();
		}
		//判断是否在下载列表中
		if(hash != null) {
			SettableListenableFuture<GetDataResult> future = downDataFutures.get(hash);
			if(future != null) {
				downDataFutures.remove(hash);
				GetDataResult getDataResult = new GetDataResult(message, result.isSuccess());
				future.set(getDataResult);
			}
			//监控同步完成
			if(monitorBlockDownload != null && monitorBlockDownload.equals(hash)) {
				notifyDownloadComplete();
			}
		}
	}

	/**
	 * 发送获取数据消息，并获取相应返回信息
	 * @param getdata
	 * @return Future<GetDataResult>
	 */
	public Future<GetDataResult> sendGetDataMessage(GetDatasMessage getdata) {
		//获取数据 ，仅一条
        Preconditions.checkArgument(getdata.getInvs().size() == 1);
        SettableListenableFuture<GetDataResult> future = new SettableListenableFuture<GetDataResult>();
        downDataFutures.put(getdata.getInvs().get(0).getHash(), future);
        try {
        	sendMessage(getdata);
        } catch (IOException e) {
        	future.set(new GetDataResult(false));
        	downDataFutures.remove(getdata.getInvs().get(0));
		}
        return future;
    }
	
	public void setMonitorBlockDownload(Sha256Hash monitorBlockDownload) {
		this.monitorBlockDownload = monitorBlockDownload;
	}

	/**
	 * 等待区块下载完成
	 * @param startHash 
	 * @throws Exception 
	 */
	public boolean waitBlockDownComplete(Sha256Hash startHash) throws Exception {
		 downloadFuture = new SettableListenableFuture<Boolean>();
		 synchronizeDataStartHash = startHash;
		 try {
			return downloadFuture.get(120, TimeUnit.SECONDS);
		} catch (InterruptedException | ExecutionException e) {
			throw e;
		}
	}
	
	/**
	 * 通知区块下载完成
	 */
	public void notifyDownloadComplete() {
		if(downloadFuture != null) {
			downloadFuture.set(true);
		}
	}
	
	@Override
	public int getMaxMessageSize() {
		return Message.MAX_SIZE;
	}
	
	@Override
	public void connectionClosed() {
		log.info("peer {} connectionClosed ", peerAddress);
		if(log.isDebugEnabled()) {
			log.debug("peer {} connectionClosed ", this);
		}
	}

	@Override
	public void connectionOpened() {
		log.info("peer {} connectionOpened ", peerAddress);
		if(log.isDebugEnabled()) {
			log.debug("peer {} connectionOpened ", this);
		}
		//发送版本信息
		
		BlockHeader bestBlock = network.getBestBlockHeader();
		try {
			VersionMessage versionMessage = new VersionMessage(network, bestBlock.getHeight(), bestBlock.getHash(), getPeerAddress());
			sendMessage(versionMessage);
			//记录发送版本的时间
			sendVersionMessageTime = System.currentTimeMillis();
		} catch (Exception e) {
			e.printStackTrace();
			log.error("发送版本信息出错：{}" , e.getMessage());
		}
	}
	
	/**
	 * 节点最新高度加1并返回最新高度
	 * @return long
	 */
	public long addAndGetBestBlockHeight() {
		return bestBlockHeight.incrementAndGet();
	}
	
	/**
	 * 获取节点最新高度
	 * @return long
	 */
	public long getBestBlockHeight() {
		if(bestBlockHeight == null) {
			return 0;
		}
		return bestBlockHeight.get();
	}
	
	@Override
	public String toString() {
		return (peerAddress == null ? "":peerAddress.toString()) + (peerVersionMessage == null ? "":peerVersionMessage.toString());
	}

	/**
	 * ping 对等体
	 * @return Future<Boolean>
	 */
	public Future<Boolean> ping() {
		SettableListenableFuture<Boolean> pingFuture = new SettableListenableFuture<Boolean>();
		long nonce = RandomUtil.randomLong();
		pingFutures.put(nonce, pingFuture);
		try {
			sendMessage(new PingMessage(nonce));
		} catch (NotYetConnectedException | IOException | CancelledKeyException e) {
			pingFuture.set(false);
			pingFutures.remove(nonce);
		}
		return pingFuture;
	}
	
	public PeerAddress getPeerAddress() {
		return peerAddress;
	}

	public NetworkParams getNetwork() {
		return network;
	}
	
	public VersionMessage getPeerVersionMessage() {
		return peerVersionMessage;
	}
	public void setPeerVersionMessage(VersionMessage peerVersionMessage) {
		this.peerVersionMessage = peerVersionMessage;
		bestBlockHeight = new AtomicLong(peerVersionMessage.getBestHeight());
	}

	public boolean isHandshake() {
		return handshake;
	}

	public void setHandshake(boolean handshake) {
		this.handshake = handshake;
	}

	public long getTimeOffset() {
		return timeOffset;
	}

	public void setTimeOffset(long timeOffset) {
		this.timeOffset = timeOffset;
	}

	public void setSendVersionMessageTime(long sendVersionMessageTime) {
		this.sendVersionMessageTime = sendVersionMessageTime;
	}
	public long getSendVersionMessageTime() {
		return sendVersionMessageTime;
	}
}
