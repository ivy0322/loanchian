package org.loanchian.network;

import org.loanchian.Configure;
import org.loanchian.core.TimeService;
import org.loanchian.utils.IpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 远程种子节点管理
 * @author ln
 *
 */
public class RemoteSeedManager implements SeedManager {
	
	private final static Logger log = LoggerFactory.getLogger(RemoteSeedManager.class);
	
	private final static Set<String> SEED_DOMAINS = new HashSet<String>(); 
	
	private List<Seed> list = new ArrayList<Seed>();
	
	private volatile boolean hasInit;
	
	public RemoteSeedManager() {
	}
	
	@Override
	public List<Seed> getSeedList(int maxConnectionCount) {
		//如果没有初始化，则先初始化
		if(!hasInit) {
			init();
		}
				
		List<Seed> newList = new ArrayList<Seed>();
		List<Seed> removeList = new ArrayList<Seed>();
		//排除连接失败且不重试的
		for (Seed seed : list) {
			if(seed.getStaus() == Seed.SEED_CONNECT_WAIT ||
				(seed.getStaus() == Seed.SEED_CONNECT_FAIL && seed.isRetry() &&
					(TimeService.currentTimeMillis() > seed.getLastTime() + seed.getRetryInterval()))) {
				newList.add(seed);
				seed.setStaus(Seed.SEED_CONNECT_ING);
			} else if(seed.getStaus() == Seed.SEED_CONNECT_FAIL && !seed.isRetry()) {
				removeList.add(seed);
			}
		}
		list.removeAll(removeList);
		return newList;
	}

	@Override
	public boolean hasMore() {
		//如果没有初始化，则先初始化
		if(!hasInit) {
			init();
		}
		for (Seed seed : list) {
			if(seed.getStaus() == Seed.SEED_CONNECT_WAIT ||
				(seed.getStaus() == Seed.SEED_CONNECT_FAIL && seed.isRetry() &&
					(TimeService.currentTimeMillis() > seed.getLastTime() + seed.getRetryInterval()))) {
				return true;
			}
		}
		return false;
	}

	public boolean add(Seed node) {
		return list.add(node);
	}
	
	/**
	 * 初始化种子节点
	 */
	private synchronized void init() {
		try {
			if(hasInit) {
				return;
			}
			if(log.isDebugEnabled()) {
				log.debug("初始化种子节点");
			}
			Set<String> myIps = IpUtil.getIps();
			for (String seedDomain : SEED_DOMAINS) {
				try {
					InetAddress[] response = InetAddress.getAllByName(seedDomain);
					for (InetAddress inetAddress : response) {
						//排除自己
						if(myIps.contains(inetAddress.getHostAddress())) {
							continue;
						}
						//若连接失败，则重试，暂定1分钟
						Seed seed = new Seed(new InetSocketAddress(inetAddress, Configure.PORT), true, 1 * 60000);
						add(seed);
					}
				} catch (Exception e) {
					log.error("种子域名{}获取出错 {}", seedDomain, e.getMessage());
				}
			}
			
			if(log.isDebugEnabled()) {
				log.debug("种子节点初始化完成");
			}
			
			hasInit = true;
		} catch (Exception e) {
			log.error("种子节点获取出错 {}", e.getMessage());
		}
	}

	/**
	 * 添加一个dns种子
	 * @param domain
	 * @return boolean
	 */
	@Override
	public boolean addDnsSeed(String domain) {
		return SEED_DOMAINS.add(domain);
	}
	
	/**
	 * 重置种子节点
	 */
	public void reset() {
		hasInit = false;
		list = new ArrayList<Seed>();
	}

	@Override
	public List<Seed> getAllSeeds(){
		return list;
	}
}
