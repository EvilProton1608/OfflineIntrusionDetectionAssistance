package monitoring1;

public class EntropyChecker {
    public static double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }

        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        int dataLength = data.length;

        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / dataLength;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }

        return entropy;
    }
}

