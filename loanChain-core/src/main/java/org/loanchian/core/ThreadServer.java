package org.loanchian.core;

import org.springframework.stereotype.Service;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 线程管理服务
 * @author ln
 *
 */
@Service
public class ThreadServer extends ThreadPoolExecutor {

	public ThreadServer() {
		this(1, 1, 0L, TimeUnit.SECONDS, new LinkedBlockingDeque<Runnable>());
	}
	
	public ThreadServer(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit,
			BlockingQueue<Runnable> workQueue) {
		super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
	}

}
