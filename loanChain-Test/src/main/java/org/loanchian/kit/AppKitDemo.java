package org.loanchian.kit;

import org.loanchian.Configure;
import org.loanchian.kits.AppKit;
import org.loanchian.network.*;

import java.io.File;
import java.net.InetSocketAddress;

public class AppKitDemo {

	public static void main(String[] args) throws Exception {
		
		SeedManager seedManager = new NodeSeedManager();
		seedManager.add(new Seed(new InetSocketAddress("127.0.0.1", 8322), true, 25000));
		
		NetworkParams network = new TestNetworkParams(seedManager);
		
		//测试前先清空帐户目录
		File dir = new File(Configure.DATA_ACCOUNT);
		if(dir.listFiles() != null) {
			for (File file : dir.listFiles()) {
				file.delete();
			}
		}
		
		final AppKit kit = new AppKit();
		kit.startSyn();
	}
}
