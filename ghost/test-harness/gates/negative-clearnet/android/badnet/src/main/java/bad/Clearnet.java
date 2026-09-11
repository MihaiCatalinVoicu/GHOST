package bad;

import javax.net.SocketFactory; // reported: 11

class ClearnetJava {
    Object proxy() {
        return java.net.Proxy.NO_PROXY; // reported: 12
    }

    Object factory() {
        return SocketFactory.getDefault();
    }
}
