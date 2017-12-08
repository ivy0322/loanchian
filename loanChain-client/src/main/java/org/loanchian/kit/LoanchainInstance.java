package org.loanchian.kit;

import javafx.fxml.FXMLLoader;
import org.loanchian.kits.AccountKit;
import org.loanchian.kits.AppKit;
import org.loanchian.kits.PeerKit;
import org.loanchian.listener.Listener;
import org.loanchian.service.impl.VersionService;
import org.loanchian.wallet.Context;
import org.loanchian.wallet.utils.DailogUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.io.IOException;
import java.net.URL;

/**
 * 核心实例
 * @author ln
 *
 */
public class LoanchainInstance {
	
	private static final Logger log = LoggerFactory.getLogger(LoanchainInstance.class);

	private static LoanchainInstance INSTANCE;
	
	private ClassPathXmlApplicationContext springContext;

	private AppKit appKit;
	private PeerKit peerKit;
	private AccountKit accountKit;
	
	private LoanchainInstance() {
		// 不允许外部创建实例
	}

	public static LoanchainInstance getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new LoanchainInstance();
		}
		return INSTANCE;
	}
	
	/**
	 * 启动核心
	 * @param netType 网络类型，1正式网络，2测试网络
	 * @throws IOException
	 */
	public void startup(int netType, Listener initListener) {
		// 通过Spring启动服务器
		String[] xmls = null;
		if(netType == 1) {
			xmls = new String[] {"classpath:/applicationContext.xml" };
		} else if(netType == 2) {
			xmls = new String[] {"classpath:/applicationContext.xml" };
		} else {
			xmls = new String[] {"classpath:/applicationContext.xml" };;
		}

		try {
			springContext = new ClassPathXmlApplicationContext(xmls);
			springContext.start();
		} catch (Exception e) {
			e.printStackTrace();
			log.info("11核心程序启动失败 {}", e.getMessage());
			return;
		}

		//启动核心
		appKit = springContext.getBean(AppKit.class);
		if(initListener != null) {
			appKit.setInitListener(initListener);
		}
		appKit.startSyn();

		VersionService versionService = springContext.getBean(VersionService.class);
		versionService.setRunModel(2);
		
		peerKit = springContext.getBean(PeerKit.class);
		accountKit = springContext.getBean(AccountKit.class);
		
		log.info("Server启动成功。");

	}

	
	public void shutdown() throws BeansException, IOException {

		springContext.stop();
		springContext.close();
		
		log.info("shutdown success");
	}
	
	public AppKit getAppKit() {
		return appKit;
	}
	public AccountKit getAccountKit() {
		return accountKit;
	}
	public PeerKit getPeerKit() {
		return peerKit;
	}
}
