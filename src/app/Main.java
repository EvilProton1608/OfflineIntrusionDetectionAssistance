package app;

import logging.LogParser;
import monitoring1.*;

import oshi.software.os.OSProcess;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

public class Main {
    public static void main(String[] args) {

        // Start resource monitoring thread: Log high memory processes
        System.out.println("\nStarting background process-focused resource monitoring...");
        Thread monitorThread = new Thread(() -> {
            try {
                while (true) {
                    List<OSProcess> highMemoryProcesses = SystemResourceMonitor.getHighMemoryProcesses(500); // 500MB+
                    try (FileWriter writer = new FileWriter("logs/high_memory_processes.log", true)) {
                        writer.write("[" + LocalDateTime.now() + "] High Memory Processes:\n");
                        for (OSProcess p : highMemoryProcesses) {
                            String info = SystemResourceMonitor.formatProcess(p);
                            writer.write(info + "\n");
                            System.out.println(info);
                        }
                        writer.write("\n");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    Thread.sleep(5000); // wait 5 seconds
                }
            } catch (InterruptedException e) {
                System.out.println("Monitoring thread interrupted.");
            }
        });
        monitorThread.setDaemon(true);
        monitorThread.start();

        // File paths
        String baselineFolder = "baseline";
        String baselineJson = "baseline/baseline.json";

        String xmlLogFile = "logs/security_event_log.xml";
        String parsedEventLogJson = "logs/security_event_log.json";
        String suspiciousProcessOutput = "logs/suspicious_process_events.json";

        String suspiciousFolder = "suspicious";
        String suspiciousScanOutput = "suspicious/suspicious_scan.json";

        String reportFolder = "reports";

        // Step 1: Generate baseline
        System.out.println("Generating baseline hashes...");
        BaselineGenerator.generateBaseline(baselineFolder, baselineJson);

        // Step 2: Parse Event Logs
        System.out.println("\nParsing Windows Event Logs...");
        LogParser parser = new LogParser();
        parser.parseSecurityLogs(xmlLogFile, parsedEventLogJson);

        // Step 3: Analyze process creation events
        System.out.println("\nAnalyzing process creation events...");
        ProcessCreationAnalyzer.analyzeProcessCreationEvents(xmlLogFile, suspiciousProcessOutput, null);

        // Step 4: Scan suspicious files
        System.out.println("\nScanning for suspicious files...");
        SuspiciousFileScanner.scanWithLogging(suspiciousFolder, baselineJson, suspiciousScanOutput, null);

        // Step 5: Generate final report
        System.out.println("\nGenerating report...");
        ReportGenerator.generateReport(suspiciousScanOutput, suspiciousProcessOutput, reportFolder);

        System.out.println("\nAll tasks completed successfully. Monitoring continues in background.");
    }
}

