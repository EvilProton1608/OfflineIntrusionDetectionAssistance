package monitoring1;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;

public class ProcessCreationAnalyzer {

    private static final Set<String> WHITELISTED_PROCESSES = new HashSet<>(Arrays.asList(
            "explorer.exe", "services.exe", "lsass.exe", "wininit.exe", "csrss.exe"
    ));

    public static void analyzeProcessCreationEvents(String xmlLogFile, String outputJsonFile, JTextArea outputArea) {
        try {
            // Parse XML document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new File(xmlLogFile));
            doc.getDocumentElement().normalize();

            NodeList events = doc.getElementsByTagName("Event");
            JSONArray suspiciousEvents = new JSONArray();
            int totalEvents = 0;
            int flaggedEvents = 0;

            for (int i = 0; i < events.getLength(); i++) {
                Element event = (Element) events.item(i);
                String eventId = getTagValue(event, "EventID");

                if (!"4688".equals(eventId)) continue; // only process creation events

                totalEvents++;

                String newProcessName = getTagValue(event, "NewProcessName");
                String parentProcessName = getTagValue(event, "ParentProcessName");
                String commandLine = getTagValue(event, "CommandLine");

                if (newProcessName == null) newProcessName = "";
                if (parentProcessName == null) parentProcessName = "";
                if (commandLine == null) commandLine = "";

                // Normalize
                newProcessName = newProcessName.toLowerCase();
                parentProcessName = parentProcessName.toLowerCase();
                commandLine = commandLine.toLowerCase();

                // Skip if whitelisted
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
                    logEntry.append("[SUSPICIOUS] ")
                            .append(newProcessName)
                            .append(" launched by ")
                            .append(parentProcessName)
                            .append("\nReasons: ")
                            .append(String.join(", ", reasons))
                            .append("\nRisk Score: ")
                            .append(riskScore)
                            .append("\n\n");

                    if (outputArea != null) {
                        outputArea.append(logEntry.toString());
                    }
                    flaggedEvents++;
                }
            }

            if (outputArea != null) {
                outputArea.append("\n[INFO] Process scan complete. Total events: " + totalEvents + ", Suspicious: " + flaggedEvents + "\n");
            }

            try (FileWriter writer = new FileWriter(outputJsonFile)) {
                writer.write(suspiciousEvents.toString(2));
                System.out.println("Suspicious process creation events saved to " + outputJsonFile);
            }

        } catch (Exception e) {
            e.printStackTrace();
            if (outputArea != null) {
                outputArea.append("[ERROR] Exception during process analysis: " + e.getMessage() + "\n");
            }
        }
    }

    private static String getTagValue(Element event, String tagName) {
        NodeList list = event.getElementsByTagName(tagName);
        if (list.getLength() == 0) return null;
        return list.item(0).getTextContent();
    }
}
