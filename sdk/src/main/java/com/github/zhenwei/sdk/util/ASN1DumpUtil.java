package com.github.zhenwei.sdk.util;

import com.github.zhenwei.core.asn1.ASN1InputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class ASN1DumpUtil {

    public static String printDump(String filePath, String targetPath) throws Exception {
        File file = new File(filePath);
        FileInputStream fileInputStream = new FileInputStream(file);
        ASN1InputStream asn1InputStream = new ASN1InputStream(fileInputStream);
        String string = com.github.zhenwei.core.asn1.util.ASN1Dump.dumpAsString(asn1InputStream.readObject(), true);
        if (StringUtils.notEmpty(targetPath)){
            File file1 = new File(targetPath);
            FileOutputStream stream = new FileOutputStream(file1);
            stream.write(string.getBytes(StandardCharsets.UTF_8));
        }
       return string;

    }



}
