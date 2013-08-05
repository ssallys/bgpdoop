package p3.hadoop.common.util;

public class Htonl2 {

	public static void main(String args[]) {
		if (args.length<1) {
			System.out.println("Usage : java Htonl2 ");
			System.exit(0);
		}

		int value=Integer.parseInt(args[0]);
		int newValue = swap(value);

		System.out.println("big endian value = 0x" + Integer.toHexString(value)
						   + ", little endian value = 0x" + Integer.toHexString(newValue));
        }

    /*
	 * Swapping byte orders of given numeric types
	 */

    static short swap(short x) {
		return (short)((x << 8) |
					   ((x >> 8) & 0xff));
    }

    static char swap(char x) {
		return (char)((x << 8) |
					  ((x >> 8) & 0xff));
    }

    static int swap(int x) {
		return (int)((swap((short)x) << 16) |
					 (swap((short)(x >> 16)) & 0xffff));
    }

    static long swap(long x) {
		return (long)(((long)swap((int)(x)) << 32) |
					  ((long)swap((int)(x >> 32)) & 0xffffffffL));
    }

    static float swap(float x) {
		return Float.intBitsToFloat(swap(Float.floatToRawIntBits(x)));
    }

    static double swap(double x) {
		return Double.longBitsToDouble(swap(Double.doubleToRawLongBits(x)));
    }

}