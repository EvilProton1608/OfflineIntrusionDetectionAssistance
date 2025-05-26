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

public class SuspiciousFileScanner {

    public static void scan(String suspiciousDir, String baselinePath, String outputJsonPath) {
        try {
            // Load baseline hashes
            Map<String, String> baselineHashes = new HashMap<>();
            JSONArray baselineArray = new JSONArray(new JSONTokener(new FileInputStream(baselinePath)));

            
            for (int i = 0; i < baselineArray.length(); i++) {
                JSONObject fileObj = baselineArray.getJSONObject(i);
                baselineHashes.put(fileObj.getString("fileName"), fileObj.getString("hash"));
            }

            // Prepare scan results using FileEvent
            List<FileEvent> fileEvents = new ArrayList<>();
            File[] suspiciousFiles = new File(suspiciousDir).listFiles();

            if (suspiciousFiles != null) {
                for (File file : suspiciousFiles) {
                    if (file.isFile()) {
                        String hash = FileHasher.hashFile(file);
                        double entropy = EntropyChecker.calculateEntropy(Files.readAllBytes(file.toPath()));  // if you want entropy too
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

            // Convert list of FileEvents to JSON
            JSONArray jsonArray = new JSONArray();
            for (FileEvent e : fileEvents) {
                JSONObject obj = new JSONObject();
                obj.put("fileName", e.getFilePath());
                obj.put("hash", e.getHash());
                obj.put("entropy", e.getEntropy());
                obj.put("highEntropy", e.getEntropy() > 7);
                obj.put("status", e.getStatus());
                jsonArray.put(obj);
            }

            // Save results to JSON file
            File outputFile = new File(outputJsonPath);
            outputFile.getParentFile().mkdirs();

            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(jsonArray.toString(2));  // pretty print
                System.out.println("Suspicious scan saved to " + outputFile.getAbsolutePath());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
