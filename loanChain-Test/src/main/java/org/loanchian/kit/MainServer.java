package org.loanchian.kit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.loanchian.Configure;
import org.loanchian.kits.AppKit;
import org.loanchian.network.Seed;
import org.loanchian.network.TestNetworkParams;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Server服务
 * 
 * @author ln
 */
public class MainServer {

	public static final Log log = LogFactory.getLog(MainServer.class);

	private static final String START = "start";
	private static final String STOP = "stop";

	private ServerSocket serverSocket;
	private ClassPathXmlApplicationContext springContext;

	public static MainServer INSTANCE;

	private MainServer() {
		// 不允许外部创建实例
	}

	public static MainServer getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new MainServer();
		}
		return INSTANCE;
	}

	public void startup() throws IOException {
		// 通过Spring启动服务器
		new Thread() {
			public void run() {
				try { 
					
					String[] xmls = null;
					if(Configure.RUN_MODE == 1) {
						xmls = new String[] { "classpath:/applicationContext-mainnet.xml", "classpath:/applicationContext.xml" };
					} else if(Configure.RUN_MODE == 2) {
						xmls = new String[] { "classpath:/applicationContext-testnet.xml", "classpath:/applicationContext.xml" };
					} else {
						xmls = new String[] { "classpath:/applicationContext-unit.xml", "classpath:/applicationContext.xml" };
					}

					springContext = new ClassPathXmlApplicationContext(xmls);
					
					springContext.start();
					
					//连接测试节点
					TestNetworkParams network = springContext.getBean(TestNetworkParams.class);
//					network.getSeedManager().add(new Seed(new InetSocketAddress("192.168.1.100", 6888)));
//					network.getSeedManager().add(new Seed(new InetSocketAddress("192.168.1.11", 6888)));
					network.getSeedManager().add(new Seed(new InetSocketAddress("192.168.1.12", 6888)));
	
					AppKit appKit = springContext.getBean(AppKit.class);
					appKit.startSyn();
					
					log.info("Server启动成功。");

				} catch (RuntimeException e) {
					e.printStackTrace();
				}
			}
		}.start();

		serverSocket = new ServerSocket(Configure.RPC_SERVER_PORT);

		// 等待关闭
		while (serverSocket != null && !serverSocket.isClosed()) {

			Socket socket = serverSocket.accept();
			InputStream is = socket.getInputStream();

			byte[] data = new byte[128];
			int i = is.read(data);

			is.close();

			if (i != -1) {

				String cmd = new String(data).trim();

				if (cmd.equals(STOP)) {
					shutdown();
					Runtime.getRuntime().exit(0);
				}
			}
		}
	}

	public void shutdown() throws IOException {

		if (serverSocket != null && !serverSocket.isClosed()) {
			serverSocket.close();
		}

		serverSocket = null;

		springContext.close();

		log.info("Server关闭成功。");
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		if (args.length != 1) {

			System.out.println("Usage: inchain <start|stop>");

			System.exit(1);
		}

		String cmd = args[0];

		MainServer server = MainServer.getInstance();

		if (cmd.equals(START)) {
			try {
				server.startup();
			} catch (IOException e) {
				System.out.println("监听端口[" + Configure.RPC_SERVER_PORT
						+ "]打开失败,错误消息:" + e.getLocalizedMessage());
				System.exit(1);
			}
		} else if (cmd.equals(STOP)) {

			Socket socket = null;
			OutputStream os = null;
			try {
				socket = new Socket("127.0.0.1", Configure.RPC_SERVER_PORT);
				os = socket.getOutputStream();
				os.write(STOP.getBytes());
			} catch (IOException e) {
				System.out.println("关闭失败,程序可能没有启动。错误消息:"
						+ e.getLocalizedMessage());
			} finally {
				try {
					if (os != null) {
						os.close();
					}
					if (socket != null) {
						socket.close();
					}
				} catch (IOException e) {
					System.out.println("关闭socket失败,错误消息:"
							+ e.getLocalizedMessage());
				}
			}
		} else {
			System.err.println("输入的启动参数非法，只允许start|stop");
		}
	}

}
