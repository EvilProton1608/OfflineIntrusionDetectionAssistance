package monitoring1;

import org.json.JSONObject;
import org.json.JSONArray;

import java.io.File;
import java.io.FileWriter;
import java.util.Objects;

public class BaselineGenerator {
    public static void generateBaseline(String baselineDir, String outputJsonPath) {
        File folder = new File(baselineDir);
        File[] files = folder.listFiles();
        JSONArray baselineArray = new JSONArray();

        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    String hash = FileHasher.hashFile(file);
                    JSONObject fileObj = new JSONObject();
                    fileObj.put("fileName", file.getName());
                    fileObj.put("hash", hash);
                    baselineArray.put(fileObj);
                }
            }
        }

        try (FileWriter writer = new FileWriter(outputJsonPath)) {
            writer.write(baselineArray.toString(2)); // Pretty print
            System.out.println("Baseline saved to " + outputJsonPath);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
