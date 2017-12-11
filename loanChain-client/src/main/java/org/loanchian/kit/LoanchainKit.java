package org.loanchian.kit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.loanchian.Configure;
import org.loanchian.kits.AppKit;
import org.loanchian.service.impl.VersionService;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Server服务
 * 
 * @author ln
 */
public class LoanchainKit {

	public static final Log log = LogFactory.getLog(LoanchainKit.class);
	
	private static final int SERVER_PORT = 13912;

	private static final String START = "start";
	private static final String STOP = "stop";

	private ServerSocket serverSocket;
	private ClassPathXmlApplicationContext springContext;

	public static LoanchainKit INSTANCE;

	private LoanchainKit() {
		// 不允许外部创建实例
	}

	public static LoanchainKit getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new LoanchainKit();
		}
		return INSTANCE;
	}

	/**
	 * 启动项目 核心
	 * @throws IOException
	 */
	public void startup() throws IOException {
		// 通过Spring启动服务器
		new Thread() {
			public void run() {
				try {
					String[] xmls  = new String[] {"classpath:/applicationContext.xml" };

					springContext = new ClassPathXmlApplicationContext(xmls);
					
					springContext.start();

					//在此启动项目核心
					AppKit appKit = springContext.getBean(AppKit.class);
					appKit.startSyn();

					//版本检测
					VersionService versionService = springContext.getBean(VersionService.class);
					versionService.setRunModel(1);
					
					log.info("Server启动成功。");

				} catch (RuntimeException e) {
					e.printStackTrace();
				}
			}
		}.start();

		serverSocket = new ServerSocket(SERVER_PORT);

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

	/**
	 * 关闭服务
	 * @throws IOException
	 */
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

		LoanchainKit server = LoanchainKit.getInstance();

		if (cmd.equals(START)) {
			try {
				server.startup();
			} catch (IOException e) {
				System.out.println("监听端口[" + SERVER_PORT
						+ "]打开失败,错误消息:" + e.getLocalizedMessage());
				System.exit(1);
			}
		} else if (cmd.equals(STOP)) {

			Socket socket = null;
			OutputStream os = null;
			try {
				socket = new Socket("127.0.0.1", SERVER_PORT);
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
