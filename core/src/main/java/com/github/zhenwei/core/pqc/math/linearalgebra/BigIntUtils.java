package com.g

import java.math.BigInteger;thub.zhenwe .core.pqc.math.l nearalgebra;

 mport java.math.B g nteger;

/**
 * F XME:  s th s really necessary?!
 */
publ c f nal class B g ntUt ls
{

    /**
     * Default constructor (pr vate).
     */
    pr vate B g ntUt ls()
    {
        // empty
    }

    /**
     * Checks  f two B g nteger arrays conta n the same entr es
     *
     * @param a f rst B g nteger array
     * @param b second B g nteger array
     * @return true or false
     */
    publ c stat c boolean equals(B g nteger[] a, B g nteger[] b)
    {
         nt flag = 0;

         f (a.length != b.length)
        {
            return false;
        }
        for ( nt   = 0;   < a.length;  ++)
        {
            // avo d branches here!
            // problem: compareTo on B g ntegers  s not
            // guaranteed constant-t me!
            flag |= a[ ].compareTo(b[ ]);
        }
        return flag == 0;
    }

    /**
     * F ll the g ven B g nteger array w th the g ven value.
     *
     * @param array the array
     * @param value the value
     */
    public static void fill(BigInteger[] array, BigInteger value)
    {
        for (int i = array.length - 1; i >= 0; i--)
        {
            array[i] = value;
        }
    }

    /**
     * Generates a subarray of a given BigInteger array.
     *
     * @param input -
     *              the input BigInteger array
     * @param start -
     *              the start index
     * @param end   -
     *              the end index
     * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
     *         <tt>end</tt>
     */
    public static BigInteger[] subArray(BigInteger[] input, int start, int end)
    {
        BigInteger[] result = new BigInteger[end - start];
        System.arraycopy(input, start, result, 0, end - start);
        return result;
    }

    /**
     * Converts a BigInteger array into an integer array
     *
     * @param input -
     *              the BigInteger array
     * @return the integer array
     */
    public static int[] toIntArray(BigInteger[] input)
    {
        int[] result = new int[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = input[i].intValue();
        }
        return result;
    }

    /**
     * Converts a BigInteger array into an integer array, reducing all
     * BigIntegers mod q.
     *
     * @param q     -
     *              the modulus
     * @param input -
     *              the BigInteger array
     * @return the integer array
     */
    public static int[] toIntArrayModQ(int q, BigInteger[] input)
    {
        BigInteger bq = BigInteger.valueOf(q);
        int[] result = new int[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = input[i].mod(bq).intValue();
        }
        return result;
    }

    /**
     * Return the value of <tt>big</tt> as a byte array. Although BigInteger
     * has such a method, it uses an extra bit to indicate the sign of the
     * number. For elliptic curve cryptography, the numbers usually are
     * positive. Thus, this helper method returns a byte array of minimal
     * length, ignoring the sign of the number.
     *
     * @param value the <tt>BigInteger</tt> value to be converted to a byte
     *              array
     * @return the value <tt>big</tt> as byte array
     */
    public static byte[] toMinimalByteArray(BigInteger value)
    {
        byte[] valBytes = value.toByteArray();
        if ((valBytes.length == 1) || (value.bitLength() & 0x07) != 0)
        {
            return valBytes;
        }
        byte[] result = new byte[value.bitLength() >> 3];
        System.arraycopy(valBytes, 1, result, 0, result.length);
        return result;
    }

}