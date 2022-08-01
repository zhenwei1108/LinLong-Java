package com.github.zhenwei.test.key;

import com.github.zhenwei.core.util.encoders.Hex;
import org.junit.Test;

public class HexTest {

    protected static final byte[] encodingTable =
            {
                    (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6',
                    (byte) '7',
                    (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e',
                    (byte) 'f'
            };

    @Test
    public void hexDemo() {
        byte[] a = {10, 91, 8,81,00,1,17};
        System.out.println(Hex.toHexString(a));

        byte[] result = new byte[a.length << 1];
        int index = 0;
        for (int i = 0; i < a.length; i++) {
            int i1 = a[i] & 0xff;
            result[index++] = encodingTable[i1 >>> 4];
            result[index++] = encodingTable[i1 & 0xf];
        }
        String hexData = new String(result);
        System.out.println(hexData);
        int length = hexData.length();
        result = new byte[hexData.length() >> 1];
        for (int i = 0; i < length; i++) {
            int i2 = getIndex(hexData.charAt(i++)) << 4;

            int index1 = getIndex(hexData.charAt(i));
            result[i >> 1] = (byte) (i2 + index1);
        }
        System.out.println(Hex.toHexString(result));


    }

    private static int getIndex(char i) {
        for (int j = 0; j < encodingTable.length; j++) {
            if (encodingTable[j] == i) {
                return j;
            }
        }
        return 0;
    }

}
