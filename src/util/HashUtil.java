package util;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

public class HashUtil {
    public static String computeSHA256(String filePath) {
        try (FileInputStream fis = new FileInputStream(new File(filePath))) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] byteArray = new byte[1024];
            int bytesCount;

            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }

            byte[] bytes = digest.digest();

            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
