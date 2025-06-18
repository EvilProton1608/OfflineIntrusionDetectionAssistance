package monitoring1;

import model.FileEvent;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.*;

import javax.swing.JTextArea;

public class SuspiciousFileScanner {

    public static void scanWithLogging(String suspiciousDir, String baselinePath, String outputTextPath, JTextArea logArea) {
        try {
            Map<String, String> baselineHashes = new HashMap<>();
            JSONArray baselineArray = new JSONArray(new JSONTokener(new FileInputStream(baselinePath)));

            for (int i = 0; i < baselineArray.length(); i++) {
                JSONObject fileObj = baselineArray.getJSONObject(i);
                baselineHashes.put(fileObj.getString("fileName"), fileObj.getString("hash"));
            }

            List<FileEvent> fileEvents = new ArrayList<>();
            File[] suspiciousFiles = new File(suspiciousDir).listFiles();

            if (suspiciousFiles != null) {
                for (File file : suspiciousFiles) {
                    if (file.isFile()) {
                        String hash = FileHasher.hashFile(file);
                        double entropy = EntropyChecker.calculateEntropy(Files.readAllBytes(file.toPath()));
                        String fileName = file.getName();

                        String status;
                        if (!baselineHashes.containsKey(fileName)) {
                            status = "Unknown";
                        } else if (baselineHashes.get(fileName).equals(hash)) {
                            status = "Known";
                        } else {
                            status = "Changed";
                        }

                        FileEvent event = new FileEvent(fileName, hash, entropy, status);
                        fileEvents.add(event);
                    }
                }
            }

            File outputFile = new File(outputTextPath);
            outputFile.getParentFile().mkdirs();

            int suspiciousCount = 0;
            int totalScanned = fileEvents.size();

            JSONArray suspiciousArray = new JSONArray();  // JSON array to store suspicious entries

            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write("==== Suspicious File Scan Report ====\n\n");

                for (FileEvent e : fileEvents) {
                    boolean isSuspicious = e.getEntropy() > 7 || "Changed".equals(e.getStatus());
                    if (isSuspicious) {
                        suspiciousCount++;

                        // Write to text report
                        writer.write("File: " + e.getFilePath() + "\n");
                        writer.write("Hash: " + e.getHash() + "\n");
                        writer.write("Entropy: " + e.getEntropy() + "\n");
                        writer.write("High Entropy: " + (e.getEntropy() > 7) + "\n");
                        writer.write("Status: " + e.getStatus() + "\n");
                        writer.write("----------------------------------------------------\n");

                        // Add to JSON array
                        JSONObject json = new JSONObject();
                        json.put("fileName", e.getFilePath());
                        json.put("hash", e.getHash());
                        json.put("entropy", e.getEntropy());
                        json.put("highEntropy", e.getEntropy() > 7);
                        json.put("status", e.getStatus());
                        suspiciousArray.put(json);
                    }
                }

                writer.write("Total files scanned: " + totalScanned + "\n");
                writer.write("Suspicious files found: " + suspiciousCount + "\n");
            }

            // ✅ Write suspicious entries as JSON array
            File jsonOutput = new File("logs/suspicious_file_scan.json");
            try (FileWriter jsonWriter = new FileWriter(jsonOutput)) {
                jsonWriter.write(suspiciousArray.toString(2)); // Pretty print
            }

            // Display in JTextArea
            logArea.setText(""); // Clear previous
            logArea.append("==== Suspicious File Scan Report ====\n\n");

            for (FileEvent e : fileEvents) {
                boolean isSuspicious = e.getEntropy() > 7 || "Changed".equals(e.getStatus());
                if (isSuspicious) {
                    logArea.append("File: " + e.getFilePath() + "\n");
                    logArea.append("Hash: " + e.getHash() + "\n");
                    logArea.append("Entropy: " + e.getEntropy() + "\n");
                    logArea.append("High Entropy: " + (e.getEntropy() > 7) + "\n");
                    logArea.append("Status: " + e.getStatus() + "\n");
                    logArea.append("----------------------------------------------------\n");
                }
            }

            logArea.append("\nTotal files scanned: " + totalScanned + "\n");
            logArea.append("Suspicious files found: " + suspiciousCount + "\n");
            logArea.append("Report saved to: " + outputFile.getAbsolutePath() + "\n");
            logArea.append("JSON report saved to: logs/suspicious_file_scan.json\n");

        } catch (Exception e) {
            logArea.append("Error during file scanning: " + e.getMessage() + "\n");
            e.printStackTrace();
        }
    }
}
