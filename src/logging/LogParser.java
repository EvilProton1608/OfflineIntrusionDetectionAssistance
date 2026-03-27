package logging;

import java.io.File;
import java.io.FileWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class LogParser {

    /**
     * Parses Windows Event Logs XML, extracts process creation info (ID 4688),
     * and saves them as JSON objects to the given path.
     *
     * @param pathToXml      Path to input XML log file.
     * @param outputJsonPath Path to save full JSON output.
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

            for (int i = 0; i < eventList.getLength(); i++) {
                Node eventNode = eventList.item(i);

                if (eventNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eventElement = (Element) eventNode;
                    String eventID = getTagValue("EventID", eventElement);

                    if ("4688".equals(eventID)) {
                        JSONObject jsonEvent = new JSONObject();
                        jsonEvent.put("EventID", eventID);

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
                            jsonEvents.put(jsonEvent);
                        }
                    }
                }
            }

            try (FileWriter writer = new FileWriter(outputJsonPath)) {
                writer.write(jsonEvents.toString(2));
                System.out.println("[INFO] Parsed Event 4688 logs saved to: " + outputJsonPath);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

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