package org.loanchian.net;

import org.loanchian.listener.NewInConnectionListener;
import org.loanchian.network.Seed;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Future;

public interface ClientConnectionManager {
	
    Future<Seed> openConnection(InetSocketAddress address, StreamConnection connection);

    int getConnectedClientCount();

    void closeConnections(int n);

    void setNewInConnectionListener(NewInConnectionListener newInConnectionListener);
    
    void start();
    
    void stop() throws IOException;
}
