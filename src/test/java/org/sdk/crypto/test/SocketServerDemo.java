package org.sdk.crypto.test;

import org.junit.jupiter.api.Test;
import org.sdk.crypto.utils.Base64Util;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class SocketServerDemo {

    @Test
    public static void server() throws Exception {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getLocalHost(), 8008));
        while (true) {
            Socket accept = socket.accept();
            InputStream inputStream = accept.getInputStream();
            OutputStream outputStream = accept.getOutputStream();
            byte[] bytes = new byte[2];

            int read = inputStream.read(bytes);
            System.out.println("server 读取消息为："+Base64Util.encodeToString(bytes));
            int i = new Random().nextInt();
            System.out.println("当前发送值为："+i);
            outputStream.write(i);
            accept.shutdownOutput();
            accept.shutdownInput();
        }

    }


    public static void client() throws Exception {
        Socket socket = new Socket(InetAddress.getLocalHost(), 8008);
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(99);
        outputStream.flush();

        byte[] bytes = new byte[111];
        int read = inputStream.read(bytes);
        System.out.println("客户端读取消息："+Base64Util.encodeToString(bytes));

        outputStream.write(99);
        outputStream.flush();
        socket.shutdownOutput();
        bytes = new byte[111];
         read = inputStream.read(bytes);
        System.out.println("1客户端读取消息："+Base64Util.encodeToString(bytes));

        outputStream.write(99);
        outputStream.flush();
        socket.shutdownOutput();
        bytes = new byte[111];
        read = inputStream.read(bytes);
        System.out.println("2客户端读取消息："+Base64Util.encodeToString(bytes));

    }



    public static void main(String[] args) throws Exception {
            new Thread(()->{
                try {
                    server();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        client();


    }


}
