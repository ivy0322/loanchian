package org.loanchian.rpc;

import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.loanchian.Configure;
import org.loanchian.utils.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 
 * 核心客户端RPC服务，RPC服务随核心启动，端口配置参考 { org.loanchian.Configure.RPC_SERVER_PORT }
 * 命令列表： help 帮助命令，列表出所有命令
 * 
 * --- 区块相关 getblockcount 获取区块的数量 getnewestblockheight 获取最新区块的高度
 * getnewestblockhash 获取最新区块的hash getblockheader [param] (block hash or height)
 * 通过区块的hash或者高度获取区块的头信息 getblock [param] (block hash or height)
 * 通过区块的hash或者高度获取区块的完整信息
 * 
 * --- 内存池 getmempoolinfo [count] 获取内存里的count条交易
 * 
 * --- 帐户 newaccount [mgpw trpw] 创建帐户，同时必需指定帐户管理密码和交易密码 getaccountaddress
 * 获取帐户的地址 getaccountpubkeys 获取帐户的公钥 dumpprivateseed 备份私钥种子，同时显示帐户的hash160
 * 
 * getbalance 获取帐户的余额 gettransaction 获取帐户的交易记录
 * 
 * ---交易相关 TODO ···
 * 
 * @author ln
 *
 */
@Service
public class RPCServer implements Server {
	
	private final static Logger log = LoggerFactory.getLogger(RPCServer.class);
	
	public final static String RPC_USER_KEY = "rpc_user";
	public final static String RPC_PASSWORD_KEY = "rpc_password";
	
	//rpc参数配置
	private final static Properties property = new Properties();

	/**
	 * RPC服务启动方法，启动之后监听本地端口 { org.loanchian.Configure.RPC_SERVER_PORT}提供服务
	 * 
	 */
	private static ExecutorService executor = Executors.newCachedThreadPool();

	@Autowired
	private RPCHanlder rpcHanlder;
	
	private ServerSocket server;
	
	private boolean isRunning = false;
	
	public void startSyn() {
		Thread t = new Thread() {
			@Override
			public void run() {
				try {
					RPCServer.this.start();
				} catch (IOException e) {
					log.error("rpc 服务报错，{}", e.getMessage(), e);
				}
			}
		};
		t.setName("rpc service");
		t.start();
		
		log.info("rpc service started");
	}

	public void start() throws IOException {
		
		init();
		log.info("will start rpc service on port {}", Integer.parseInt(property.getProperty("rpc_port")));
		server = new ServerSocket(Integer.parseInt(property.getProperty("rpc_port")));
		server.setReuseAddress(true);
		
		log.debug("rpc service started");
		isRunning = true;
		while (isRunning) {
			// 1.监听客户端的TCP连接，接到TCP连接后将其封装成task，由线程池执行
			try {
				executor.execute(new RPCRequestCertification(server.accept()));
			} catch (Exception e) {
				try {
					Thread.sleep(100l);
				} catch (InterruptedException e1) {
				}
			}
		}
	}

	/*
	 * rpc请求认证
	 * @author ln
	 *
	 */
	class RPCRequestCertification implements Runnable {

		private Socket socket;
		private BufferedReader br;
		private PrintWriter pw;
		
		public RPCRequestCertification(Socket socket) throws IOException {
			socket.setReuseAddress(true);
			this.socket = socket;
			this.br = new BufferedReader(new InputStreamReader(socket.getInputStream(), "utf-8"));
			this.pw = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "utf-8"));
		}
		
		@Override
		public void run() {
			try {
				JSONObject certificationInfo = readMessage();
				if(certificationInfo == null) {
					writeMessage(false, "解析rpc命令失败");
					return;
				}
				if(!certificationInfo.has(RPC_USER_KEY) || !certificationInfo.has(RPC_PASSWORD_KEY) || 
						!property.getProperty(RPC_USER_KEY).equals(certificationInfo.getString(RPC_USER_KEY))
						|| !property.getProperty(RPC_PASSWORD_KEY).equals(certificationInfo.getString(RPC_PASSWORD_KEY))) {
					writeMessage(false, "rpc认证失败");
					return;
				}
				
				//认证通过，处理业务逻辑
				writeMessage(true, "ok");
				
				while(true) {
					JSONObject commandInfos = readMessage();
					if(commandInfos == null) {
						writeMessage(false, "rpc命令获取失败");
						return;
					}
					
					JSONObject result = rpcHanlder.hanlder(commandInfos);
					
					if(result.has("needInput") && result.getBoolean("needInput")) {
						writeMessage(result);
						JSONObject inputInfos = readMessage();
						result = rpcHanlder.hanlder(commandInfos, inputInfos);
						writeMessage(result);
					} else {
						writeMessage(result);
					}
				}
			} catch (JSONException | IOException e) {
				try {
					writeMessage(false, "rpc命令错误,详情:" + e.getMessage());
				} catch (JSONException e1) {
					e1.printStackTrace();
				}
			} finally {
				try {
					close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
		private JSONObject readMessage() throws JSONException, IOException {
			String message = br.readLine().trim();
			if(StringUtil.isEmpty(message)) {
				return null;
			} else {
				if(message.charAt(0) != '{' && message.charAt(0) != '[') {
					message = message.substring(Configure.RPC_HEAD_LENGTH);
				}
				return new JSONObject(message);
			}
		}
		
		private void writeMessage(boolean success, String msg) throws JSONException {
			JSONObject result = new JSONObject();
			result.put("success", success);
			result.put("message", msg);
			writeMessage(result);
		}
		
		private void writeMessage(JSONObject result) throws JSONException {
			//写出消息时，抬头写出消息的固定8位长度
			String info = result.toString().trim();
			String regix = "00000000";
			String len = info.length()+"";
			String head = regix.substring(len.length())+len;

			pw.println(head + info);
			pw.flush();
		}

		public void close() throws IOException {
			br.close();
			pw.close();
			socket.close();
		}
	}
	
	/*
	 * 初始化rpc服务参数，如果有配置文件，则读取配置文件
	 * 如果没有配置文件，则生成新的rpc配置文件
	 */
	private void init() throws IOException {
		//判断配置文件是否存在
		InputStream in = RPCServer.class.getResourceAsStream("/rpc_config.properties");
		if(in != null) {
			property.load(in);
			in.close();
		}
		boolean refresh = false;
		if(!property.containsKey("rpc_host")) {
			refresh = true;
			property.put("rpc_host", Configure.RPC_SERVER_HOST);
		}
		if(!property.containsKey("rpc_port")) {
			refresh = true;
			property.put("rpc_port", "" + Configure.RPC_SERVER_PORT);
		}
		if(!property.containsKey(RPC_USER_KEY)) {
			refresh = true;
			property.put(RPC_USER_KEY, Configure.RPC_SERVER_USER);
		}
		if(!property.containsKey(RPC_PASSWORD_KEY)) {
			refresh = true;
			property.put(RPC_PASSWORD_KEY, StringUtil.randStr(20, 0));
		}
		
		//回写
		if(refresh) {
			if(RPCServer.class.getResource("/") == null) {
				return;
			}
			FileOutputStream os = new FileOutputStream(RPCServer.class.getResource("/").getPath()+"rpc_config.properties");
			
			property.store(os, "this is rpc server configs");
			
			os.close();
		}
	}

	public void stop() {
		isRunning = false;

		try {
			if(server != null) {
				server.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
