package monitoring1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JTextArea;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import model.FileEvent;

public class SuspiciousFileScanner {

    public static void scanWithLogging(String suspiciousDir, String baselinePath, String outputTextPath, String outputJsonPath, JTextArea logArea) {
        try {
            Map<String, String> baselineHashes = new HashMap<>(); //map
            JSONArray baselineArray = new JSONArray(new JSONTokener(new FileInputStream(baselinePath))); //fill baseline array by basline.json

            for (int i = 0; i < baselineArray.length(); i++) {
                JSONObject fileObj = baselineArray.getJSONObject(i);
                baselineHashes.put(fileObj.getString("fileName"), fileObj.getString("hash")); //basline array to basline hashes map
            }

            List<FileEvent> fileEvents = new ArrayList<>(); //for printing
            File[] suspiciousFiles = new File(suspiciousDir).listFiles(); //files from SYSTEM32

            if (suspiciousFiles != null) {
                for (File file : suspiciousFiles) { //traversing suspicious_files array
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

                        fileEvents.add(new FileEvent(fileName, hash, entropy, status));
                    }
                }
            }

            int suspiciousCount = 0;
            int totalScanned = fileEvents.size();

            JSONArray suspiciousArray = new JSONArray();

            // Write text report
            File textFile = new File(outputTextPath);
            textFile.getParentFile().mkdirs();

            try (FileWriter writer = new FileWriter(textFile)) {
                writer.write("==== Suspicious File Scan Report ====\n\n");
                for (FileEvent e : fileEvents) {
                    boolean isSuspicious = e.getEntropy() > 7 || "Changed".equals(e.getStatus())|| "Unknown".equals(e.getStatus());
                    if (isSuspicious) {
                        suspiciousCount++;
                        writer.write("File: " + e.getFilePath() + "\n");
                        writer.write("Hash: " + e.getHash() + "\n");
                        writer.write("Entropy: " + e.getEntropy() + "\n");
                        writer.write("High Entropy: " + (e.getEntropy() > 7) + "\n");
                        writer.write("Status: " + e.getStatus() + "\n");
                        writer.write("----------------------------------------------------\n");

                        // Add to JSON
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

            // Write JSON report
            File jsonFile = new File(outputJsonPath);
            jsonFile.getParentFile().mkdirs();

            try (FileWriter jsonWriter = new FileWriter(jsonFile)) {
                jsonWriter.write(suspiciousArray.toString(2)); // Pretty print
            }

            // Display in GUI (optional)
            if (logArea != null) {
                logArea.setText("==== Suspicious File Scan Report ====\n\n");
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
                logArea.append("Report saved to: " + textFile.getAbsolutePath() + "\n");
                logArea.append("JSON report saved to: " + jsonFile.getAbsolutePath() + "\n");
            }

        } catch (Exception e) {
            if (logArea != null) {
                logArea.append("Error during file scanning: " + e.getMessage() + "\n");
            }
            e.printStackTrace();
        }
    }
}
