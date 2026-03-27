package monitoring1;

import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ReportGenerator {

    public static String generateReport(String suspiciousScanPath, String suspiciousProcessPath, String outputFolder) {
        try {
            // Read and validate JSON files
            String scanContent = readFileAsString(suspiciousScanPath);
            String processContent = readFileAsString(suspiciousProcessPath);

            // Parse JSON Arrays
            JSONArray suspiciousFiles = new JSONArray(scanContent);
            JSONArray suspiciousProcesses = new JSONArray(processContent);

            StringBuilder report = new StringBuilder();
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

            report.append("===== Offline Intrusion Detection System Report =====\n");
            report.append("Report Generated At: ").append(timestamp).append("\n\n");

            // Count high entropy files
            int suspiciousFileCount = suspiciousFiles.length();
            int highEntropyCount = 0;
            for (int i = 0; i < suspiciousFiles.length(); i++) {
                JSONObject file = suspiciousFiles.getJSONObject(i);
                if (file.optBoolean("highEntropy", false)) highEntropyCount++;
            }

            // Summary section
            report.append("Summary:\n");
            report.append("Suspicious Files: ").append(suspiciousFileCount).append("\n");
            report.append("High Entropy Files: ").append(highEntropyCount).append("\n");
            report.append("Suspicious Processes: ").append(suspiciousProcesses.length()).append("\n\n");

            // Suspicious files section
            report.append("Suspicious Files:\n");
            for (int i = 0; i < suspiciousFiles.length(); i++) {
                JSONObject file = suspiciousFiles.getJSONObject(i);
                report.append("File: ").append(file.optString("fileName")).append("\n");
                report.append("Status: ").append(file.optString("status")).append("\n");
                report.append("Entropy: ").append(file.optDouble("entropy")).append("\n");
                report.append("High Entropy: ").append(file.optBoolean("highEntropy")).append("\n");
                report.append("Hash: ").append(file.optString("hash")).append("\n\n");
            }

            // Suspicious processes section
            report.append("Suspicious Processes:\n");
            if (suspiciousProcesses.length() == 0) {
                report.append("None detected.\n\n");
            } else {
                for (int i = 0; i < suspiciousProcesses.length(); i++) {
                    JSONObject process = suspiciousProcesses.getJSONObject(i);
                    report.append(process.toString(2)).append("\n\n");
                }
            }

            // Save report
            String fileName = "report_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".txt";
            File outputFile = new File(outputFolder, fileName);
            outputFile.getParentFile().mkdirs();

            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(report.toString());
            }

            System.out.println("Report saved to " + outputFile.getAbsolutePath());
            return outputFile.getAbsolutePath();

        } catch (JSONException je) {
            je.printStackTrace();
            return "Error: Could not parse JSON array.\n" + je.getMessage();
        } catch (FileNotFoundException fe) {
            fe.printStackTrace();
            return "Error: One or more input files not found.";
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return "Error reading or writing files: " + ioe.getMessage();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error generating report: " + e.getMessage();
        }
    }

    // Validates JSON as JSONArray and returns raw string content
    private static String readFileAsString(String path) throws IOException {
        File file = new File(path);
        if (!file.exists() || file.length() == 0) {
            throw new FileNotFoundException("Missing or empty file: " + path);
        }

        String content = new String(Files.readAllBytes(Paths.get(path))).trim();

        try {
            // Validate by attempting to parse
            new JSONArray(content);
        } catch (JSONException e) {
            System.err.println("Invalid JSON content in file: " + path);
            System.err.println("Content: " + content);
            throw new JSONException("Invalid JSON format in file [" + path + "]: expected a JSONArray. " + e.getMessage());
        }

        return content;
    }
}
