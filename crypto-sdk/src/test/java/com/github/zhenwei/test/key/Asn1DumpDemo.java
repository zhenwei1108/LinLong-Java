package com.github.zhenwei.test.key;

import com.github.zhenwei.sdk.util.ASN1DumpUtil;

public class Asn1DumpDemo {
    public static void main(String[] args) throws Exception {
        String s = ASN1DumpUtil.printDump("/Users/zhangzhenwei/Downloads/大文件/2_Sign.p7s", "/Users/zhangzhenwei/asn.txt");
        System.out.println(s);
    }
}
