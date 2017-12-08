package org.loanchian.net;

import org.loanchian.Configure;
import org.loanchian.core.Peer;
import org.loanchian.core.PeerAddress;
import org.loanchian.listener.NewInConnectionListener;
import org.loanchian.network.NetworkParams;
import org.loanchian.network.Seed;
import org.loanchian.utils.ContextPropagatingThreadFactory;
import org.loanchian.utils.Utils;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.*;
import java.nio.channels.spi.SelectorProvider;
import java.util.*;
import java.util.concurrent.*;

/**
 * A class which manages a set of client connections. Uses Java NIO to select network events and processes them in a
 * single network processing thread.
 */
@Service
public class NioClientManager implements ClientConnectionManager {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(NioClientManager.class);

    private final ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1);
    
    @Autowired
    private NetworkParams network;
    
    private Selector selector;
    
    //被动连接监听
    private NewInConnectionListener newInConnectionListener;
    
    private boolean isServer = true; //是否启动本地监听服务 ， SPV就不需要
    private ServerSocket serverSocket;
    private ServerSocketChannel serverSocketChannel;
    
    public NioClientManager() {
    	try {
            selector = SelectorProvider.provider().openSelector();
            if(this.isServer) {
	            // 打开服务器套接字通道  
	            serverSocketChannel = ServerSocketChannel.open();  
	            // 服务器配置为非阻塞  
	            serverSocketChannel.configureBlocking(false);  
	            // 检索与此通道关联的服务器套接字  
	            serverSocket = serverSocketChannel.socket();  
	            // 进行服务的绑定  
	            serverSocket.bind(new InetSocketAddress(Configure.PORT));  
	            // 注册到selector，等待连接  
	            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);  
	            log.info("Server Started on port {}", Configure.PORT);
            }
        } catch (IOException e) {
            throw new RuntimeException(e); // Shouldn't ever happen
        }
	}

    
    class PendingConnect {
        SocketChannel sc;
        StreamConnection connection;
        Future<Seed> future = new CompletableFuture<Seed>();

        PendingConnect(SocketChannel sc, StreamConnection connection) { this.sc = sc; this.connection = connection;}
    }
    final Queue<PendingConnect> newConnectionChannels = new LinkedBlockingQueue<PendingConnect>();

    // Added to/removed from by the individual ConnectionHandler's, thus must by synchronized on its own.
    private final Set<ConnectionHandler> connectedHandlers = Collections.synchronizedSet(new HashSet<ConnectionHandler>());

    // Handle a SelectionKey which was selected
    private void handleKey(SelectionKey key) throws IOException {
        // We could have a !isValid() key here if the connection is already closed at this point
        if (key.isValid() && key.isConnectable()) { // ie a client connection which has finished the initial connect process
            // Create a ConnectionHandler and hook everything together
            PendingConnect data = (PendingConnect) key.attachment();
            StreamConnection connection = data.connection;
            SocketChannel sc = (SocketChannel) key.channel();
            ConnectionHandler handler = new ConnectionHandler(connection, key, connectedHandlers);
            try {
                if (sc.finishConnect()) {
                	if(log.isDebugEnabled()) {
                		log.debug("Connected to {}", sc.socket().getRemoteSocketAddress());
                	}
                    key.interestOps((key.interestOps() | SelectionKey.OP_READ) & ~SelectionKey.OP_CONNECT).attach(handler);
                    connection.connectionOpened();
                } else {
                    log.warn("Failed to connect to {}", sc.socket().getRemoteSocketAddress());
                    handler.closeConnection(); // Failed to connect for some reason
                }
            } catch (Exception e) {
                // If e is a CancelledKeyException, there is a race to get to interestOps after finishConnect() which
                // may cause this. Otherwise it may be any arbitrary kind of connection failure.
                // Calling sc.socket().getRemoteSocketAddress() here throws an exception, so we can only log the error itself
                log.warn("Failed connect to {} with exception: {}", connection, e.getMessage());
                handler.closeConnection();
            }
        } else {
        	ConnectionHandler handler = ((ConnectionHandler)key.attachment());
            if (handler == null) {
            	if(key.isValid() && key.isAcceptable()) {
	            	ServerSocketChannel sc = (ServerSocketChannel) key.channel();
	            	SocketChannel socketChannel = sc.accept();
	            	
	            	if(newInConnectionListener == null || !newInConnectionListener.allowConnection((InetSocketAddress)socketChannel.getRemoteAddress())) {
	            		log.info("refush connection on " + socketChannel.getRemoteAddress());
	            		socketChannel.close();
	            		return;
	            	}
	            	
                    // 配置为非阻塞  
            		socketChannel.configureBlocking(false);
            		SelectionKey newKey = socketChannel.register(selector, SelectionKey.OP_READ);
//            		key.cancel();
            		
            		Peer peer = new Peer(network, new PeerAddress((InetSocketAddress)socketChannel.getRemoteAddress())) {
            			@Override
            			public void connectionOpened() {
            				super.connectionOpened();
            			}
                		@Override
                		public void connectionClosed() {
                			if(newInConnectionListener != null) 
                				newInConnectionListener.connectionClosed(this);
                		}
                	};
            		handler = new ConnectionHandler(peer, newKey, socketChannel, connectedHandlers);
            		newKey.attach(handler);
		      		peer.connectionOpened();
            		
            		if(newInConnectionListener != null) 
        				newInConnectionListener.connectionOpened(peer);
                    
                    return;
                }
            }
            
        	// Process bytes read
        	ConnectionHandler.handleKey(key);
        }
    }

	@Override
    public void start() {
//    	executor.scheduleWithFixedDelay(this, 0, 1, TimeUnit.SECONDS);
    	new Thread() {
    		public void run() {
    			NioClientManager.this.run();
    		};
    	}.start();
    }

	@Override
    public void stop() throws IOException {
    	executor.shutdownNow();
    	
    	triggerShutdown();
    	
        try {
        	serverSocket.close();
        	serverSocketChannel.close();
        } catch (Exception e) {
        	log.warn("Error closing serverSocket", e);
		}
        log.info("stoped service");
    }

    public void run() {
        try {
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
            
            while (!executor.isShutdown()) {
                PendingConnect conn;
                while ((conn = newConnectionChannels.poll()) != null) {
                    try {
                        SelectionKey key = conn.sc.register(selector, SelectionKey.OP_CONNECT);
                        key.attach(conn);
                    } catch (ClosedChannelException e) {
                        log.warn("SocketChannel was closed before it could be registered");
                    }
                }

                selector.select();

                Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    keyIterator.remove();
                    handleKey(key);
                }
            }
        } catch (Exception e) {
            log.warn("Error trying to open/read from connection: ", e);
        } finally {
            
            // Go through and close everything, without letting IOExceptions get in our way
            for (SelectionKey key : selector.keys()) {
                try {
                    key.channel().close();
                } catch (IOException e) {
                    log.warn("Error closing channel", e);
                }
                key.cancel();
                if (key.attachment() instanceof ConnectionHandler)
                    ConnectionHandler.handleKey(key); // Close connection if relevant
            }
            try {
            	selector.close();
            } catch (IOException e) {
            	log.warn("Error closing client manager selector", e);
            }
        }
    }

	@Override
    public Future<Seed> openConnection(InetSocketAddress address, StreamConnection connection) {
        if (executor.isShutdown())
            throw new IllegalStateException();
        // address not null
        Utils.checkNotNull(address);
        try {
            SocketChannel sc = SocketChannel.open();
            sc.configureBlocking(false);
            sc.socket().setReuseAddress(true);
            sc.connect(address);
            PendingConnect data = new PendingConnect(sc, connection);
            newConnectionChannels.offer(data);
            selector.wakeup();
            return data.future;
        } catch (Throwable e) {
            return null;
        }
    }

    public void triggerShutdown() {
        selector.wakeup();
    }

    @Override
    public int getConnectedClientCount() {
        return connectedHandlers.size();
    }

    @Override
    public void closeConnections(int n) {
        while (n-- > 0) {
            ConnectionHandler handler;
            synchronized (connectedHandlers) {
                handler = connectedHandlers.iterator().next();
            }
            if (handler != null)
                handler.closeConnection(); // Removes handler from connectedHandlers before returning
        }
    }
    
    public void setNewInConnectionListener(NewInConnectionListener newInConnectionListener) {
		this.newInConnectionListener = newInConnectionListener;
	}

    protected Executor executor() {
        return new Executor() {
            @Override
            public void execute(Runnable command) {
                new ContextPropagatingThreadFactory("NioClientManager").newThread(command).start();
            }
        };
    }
}
