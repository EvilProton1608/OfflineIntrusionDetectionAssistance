package app;

import logging.LogParser;
import monitoring1.*;

public class Main {
    public static void main(String[] args) {

        // -> for baseline
        String baselineFolder = "baseline";
        String baselineJson = "baseline/baseline.json";

        // -> loading event logs
        String xmlLogFile = "logs/security_event_log.xml";
        String parsedEventLogJson = "logs/security_event_log.json";
        String suspiciousProcessOutput = "logs/suspicious_process_events.json";

        // -> scan suspicious files
        String suspiciousFolder = "suspicious";
        String suspiciousScanOutput = "suspicious/suspicious_scan.json";

        // -> final report
        String reportFolder = "reports";

        // 1. Generate baseline (optional: run once or regenerate as needed)
        System.out.println("Generating baseline hashes...");
        BaselineGenerator.generateBaseline(baselineFolder, baselineJson);

        // 2. Parse Event Logs
        System.out.println("\nParsing Windows Event Logs...");
        LogParser parser = new LogParser();
        parser.parseSecurityLogs(xmlLogFile, parsedEventLogJson);

        // 3. Analyze process creation events
        System.out.println("\nAnalyzing process creation events...");
        ProcessCreationAnalyzer.analyzeProcessCreationEvents(xmlLogFile, suspiciousProcessOutput);

        // 4. Scan suspicious files (compare against baseline)
        System.out.println("\nScanning for suspicious files...");
        SuspiciousFileScanner.scan(suspiciousFolder, baselineJson, suspiciousScanOutput);

        // 5. Generate report
        System.out.println("\nGenerating report...");
        ReportGenerator.generateReport(suspiciousScanOutput, suspiciousProcessOutput, reportFolder);

        System.out.println("\nAll tasks completed successfully.");
    }
}
