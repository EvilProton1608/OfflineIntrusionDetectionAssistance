package logging;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.json.JSONArray;
import org.json.JSONObject;

import org.w3c.dom.*;

import java.io.File;
import java.io.FileWriter;

public class LogParser {

    /** 
     * Parses Windows Event Logs XML, converts to JSON, and saves to output path.
     * 
     * @param pathToXml      Path to input XML log file.
     * @param outputJsonPath Path to save JSON output file.
     */
	public void parseSecurityLogs(String pathToXml, String outputJsonPath) {
	    try {
	        File xmlFile = new File(pathToXml);
	        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
	        Document doc = dBuilder.parse(xmlFile);

	        doc.getDocumentElement().normalize();

	        NodeList eventList = doc.getElementsByTagName("Event");

	        JSONArray jsonEvents = new JSONArray();
	        JSONArray suspiciousProcessEvents = new JSONArray();

	        for (int i = 0; i < eventList.getLength(); i++) {
	            Node eventNode = eventList.item(i);

	            if (eventNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element eventElement = (Element) eventNode;

	                String eventID = getTagValue("EventID", eventElement);
	                String timeCreated = extractTimeCreated(eventElement);

	                JSONObject jsonEvent = new JSONObject();
	                jsonEvent.put("EventID", eventID);
	                jsonEvent.put("TimeCreated", timeCreated);

	                if (eventID.equals("4688")) {
	                    // Parse detailed EventData for process creation
	                    Element eventData = (Element) eventElement.getElementsByTagName("EventData").item(0);
	                    if (eventData != null) {
	                        JSONObject eventDataJson = new JSONObject();

	                        NodeList dataList = eventData.getElementsByTagName("Data");
	                        for (int j = 0; j < dataList.getLength(); j++) {
	                            Element dataElem = (Element) dataList.item(j);
	                            String name = dataElem.getAttribute("Name");
	                            String value = dataElem.getTextContent();
	                            eventDataJson.put(name, value);
	                        }
	                        jsonEvent.put("EventData", eventDataJson);

	                        // Now check suspicious logic
	                        if (isSuspiciousProcessCreation(eventDataJson)) {
	                            suspiciousProcessEvents.put(jsonEvent);
	                        }
	                    }
	                } else {
	                    // For other events, just get Message
	                    String message = getTagValue("Message", eventElement);
	                    jsonEvent.put("Message", message);
	                }
	                jsonEvents.put(jsonEvent);
	            }
	        }

	        // Write all events to outputJsonPath (optional)
	        try (FileWriter writer = new FileWriter(outputJsonPath)) {
	            writer.write(jsonEvents.toString(2));
	            System.out.println("Event log JSON saved to " + outputJsonPath);
	        }

	        // Write suspicious process events separately
	        try (FileWriter writer = new FileWriter("logs/suspicious_process_events.json")) {
	            writer.write(suspiciousProcessEvents.toString(2));
	            System.out.println("Suspicious process events saved to logs/suspicious_process_events.json");
	        }

	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}

	private String extractTimeCreated(Element eventElement) {
	    Element systemElem = (Element) eventElement.getElementsByTagName("System").item(0);
	    String timeCreated = "Unknown";
	    if (systemElem != null) {
	        NodeList timeCreatedList = systemElem.getElementsByTagName("TimeCreated");
	        if (timeCreatedList != null && timeCreatedList.getLength() > 0) {
	            Node timeNode = timeCreatedList.item(0);
	            if (timeNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element timeElem = (Element) timeNode;
	                timeCreated = timeElem.getAttribute("SystemTime");
	            }
	        }
	    }
	    return timeCreated;
	}

	private boolean isSuspiciousProcessCreation(JSONObject eventData) {
	    String newProcessName = eventData.optString("NewProcessName", "").toLowerCase();
	    String commandLine = eventData.optString("CommandLine", "").toLowerCase();

	    // Define suspicious indicators
	    String[] suspiciousProcesses = { "powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe" };
	    boolean suspiciousName = false;
	    for (String sp : suspiciousProcesses) {
	        if (newProcessName.contains(sp)) {
	            suspiciousName = true;
	            break;
	        }
	    }

	    boolean encodedCmd = commandLine.contains("-encodedcommand") || commandLine.contains("base64");

	    return suspiciousName || encodedCmd;
	}

    // Helper method to get text content of a tag inside an element
    private String getTagValue(String tag, Element element) {
        NodeList nodeList = element.getElementsByTagName(tag);
        if (nodeList != null && nodeList.getLength() > 0) {
            Node node = nodeList.item(0);
            if (node != null && node.getFirstChild() != null) {
                return node.getFirstChild().getNodeValue();
            }
        }
        return "";
    }
}
