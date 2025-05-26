package monitoring1;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

public class ProcessCreationAnalyzer {

    public static void analyzeProcessCreationEvents(String xmlLogFile, String outputJsonFile) {
        try {
            // Parse XML document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new File(xmlLogFile));
            doc.getDocumentElement().normalize();

            NodeList events = doc.getElementsByTagName("Event");
            JSONArray suspiciousEvents = new JSONArray();

            for (int i = 0; i < events.getLength(); i++) {
                Element event = (Element) events.item(i);
                String eventId = getTagValue(event, "EventID");

                if (!"4688".equals(eventId)) continue; // only process creation events

                String newProcessName = getTagValue(event, "NewProcessName");
                String parentProcessName = getTagValue(event, "ParentProcessName");
                String commandLine = getTagValue(event, "CommandLine");

                if (newProcessName == null) newProcessName = "";
                if (parentProcessName == null) parentProcessName = "";
                if (commandLine == null) commandLine = "";

                boolean suspicious = false;
                List<String> reasons = new ArrayList<>();

                // Rule 1: powershell.exe launched by explorer.exe with -enc argument
                if (parentProcessName.toLowerCase().contains("explorer.exe") &&
                    newProcessName.toLowerCase().contains("powershell.exe") &&
                    commandLine.toLowerCase().contains("-enc")) {
                    suspicious = true;
                    reasons.add("Powershell encoded command launched by explorer.exe");
                }

                // Rule 2: command line contains Invoke-Expression or Base64
                if (commandLine.toLowerCase().contains("invoke-expression") ||
                    commandLine.toLowerCase().contains("base64")) {
                    suspicious = true;
                    reasons.add("Command line contains suspicious keywords");
                }

                // Rule 3: LOLBins execution
                String[] lolBins = {"certutil.exe", "mshta.exe", "wmic.exe"};
                for (String bin : lolBins) {
                    if (newProcessName.toLowerCase().contains(bin)) {
                        suspicious = true;
                        reasons.add("Known LOLBin executed: " + bin);
                        break;
                    }
                }

                if (suspicious) {
                    JSONObject suspiciousEvent = new JSONObject();
                    suspiciousEvent.put("newProcessName", newProcessName);
                    suspiciousEvent.put("parentProcessName", parentProcessName);
                    suspiciousEvent.put("commandLine", commandLine);
                    suspiciousEvent.put("reasons", reasons);
                    suspiciousEvents.put(suspiciousEvent);
                }
            }

            // Write suspicious events to JSON file
            try (FileWriter writer = new FileWriter(outputJsonFile)) {
                writer.write(suspiciousEvents.toString(2));
                System.out.println("Suspicious process creation events saved to " + outputJsonFile);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getTagValue(Element event, String tagName) {
        NodeList list = event.getElementsByTagName(tagName);
        if (list.getLength() == 0) return null;
        return list.item(0).getTextContent();
    }
}

//demo -> powershell.exe -EncodedCommand JABXAGUAYgAuAGUAYwBoAG8AIAAiSGVsbG8gd29ybGQi
//2-> cmd.exe /c net user eviluser P@ssw0rd /add

