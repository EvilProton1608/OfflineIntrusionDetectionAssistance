package monitoring1;

import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ReportGenerator {

    public static void generateReport(String suspiciousScanPath, String suspiciousProcessPath, String outputFolder) {
        try {
            JSONArray suspiciousFiles = new JSONArray(new JSONTokener(new FileInputStream(suspiciousScanPath)));
            JSONArray suspiciousProcesses = new JSONArray(new JSONTokener(new FileInputStream(suspiciousProcessPath)));

            JSONObject report = new JSONObject();

            // Timestamp
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            report.put("reportGeneratedAt", timestamp);

            // Summary counts
            int suspiciousFileCount = suspiciousFiles.length();
            int suspiciousProcessCount = suspiciousProcesses.length();
            int highEntropyCount = 0;

            for (int i = 0; i < suspiciousFiles.length(); i++) {
                JSONObject file = suspiciousFiles.getJSONObject(i);
                if (file.optBoolean("highEntropy", false)) {
                    highEntropyCount++;
                }
            }

            JSONObject summary = new JSONObject();
            summary.put("suspiciousFileCount", suspiciousFileCount);
            summary.put("highEntropyFileCount", highEntropyCount);
            summary.put("suspiciousProcessCount", suspiciousProcessCount);
            report.put("summary", summary);

            // Details
            report.put("suspiciousFiles", suspiciousFiles);
            report.put("suspiciousProcesses", suspiciousProcesses);

            // Write to output file
            String fileName = "report_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".json";
            Path outputPath = Paths.get(outputFolder, fileName);
            Files.createDirectories(outputPath.getParent());

            try (FileWriter writer = new FileWriter(outputPath.toFile())) {
                writer.write(report.toString(2)); // pretty print
                System.out.println("Report saved to " + outputPath.toAbsolutePath());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
