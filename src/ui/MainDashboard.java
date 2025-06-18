package ui;

import monitoring1.*;
import oshi.software.os.OSProcess;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

public class MainDashboard {

    private static JTextArea outputArea;

    public static void main(String[] args) {
        // Set dark theme look and feel
        UIManager.put("Panel.background", new Color(40, 44, 52));
        UIManager.put("OptionPane.background", new Color(40, 44, 52));
        UIManager.put("OptionPane.messageForeground", Color.WHITE);
        UIManager.put("Button.background", new Color(60, 63, 65));
        UIManager.put("Button.foreground", Color.WHITE);
        UIManager.put("TextArea.background", new Color(30, 32, 34));
        UIManager.put("TextArea.foreground", Color.WHITE);
        UIManager.put("TextArea.caretForeground", Color.WHITE);
        UIManager.put("TabbedPane.background", new Color(40, 44, 52));
        UIManager.put("TabbedPane.foreground", Color.WHITE);
        UIManager.put("ScrollPane.background", new Color(40, 44, 52));

        JFrame frame = new JFrame("Offline Intrusion Detection System");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000, 700);
        frame.setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        // Panel 1: Resource Monitor
        JPanel resourcePanel = new JPanel(new BorderLayout());
        JButton refreshButton = createButton("Refresh High-Memory Processes");
        JTextArea processArea = createTextArea();

        refreshButton.addActionListener(e -> {
            outputArea.append("[INFO] Checking for high-memory processes...\n");
            List<OSProcess> processes = SystemResourceMonitor.getHighMemoryProcesses(500);
            StringBuilder sb = new StringBuilder();
            for (OSProcess p : processes) {
                String info = SystemResourceMonitor.formatProcess(p);
                sb.append(info).append("\n");
                outputArea.append("[PROCESS] " + info + "\n");
            }
            processArea.setText(sb.toString());
        });

        resourcePanel.add(refreshButton, BorderLayout.NORTH);
        resourcePanel.add(new JScrollPane(processArea), BorderLayout.CENTER);

        // Panel 2: Suspicious File Scan
        JPanel fileScanPanel = new JPanel(new BorderLayout());
        JButton fileScanButton = createButton("Run Suspicious File Scan");
        JTextArea scanStatusArea = createTextArea();
        fileScanPanel.add(fileScanButton, BorderLayout.NORTH);
        fileScanPanel.add(new JScrollPane(scanStatusArea), BorderLayout.CENTER);

        fileScanButton.addActionListener(e -> {
            outputArea.append("[INFO] Starting suspicious file scan...\n");
            new Thread(() -> {
                try {
                    SuspiciousFileScanner.scanWithLogging("suspicious/", "baseline/baseline.json", "logs/suspicious_file_scan.txt", scanStatusArea);
                    outputArea.append("[SUCCESS] File scan completed.\n");
                } catch (Exception ex) {
                    outputArea.append("[ERROR] File scan failed: " + ex.getMessage() + "\n");
                    ex.printStackTrace();
                }
            }).start();
        });

        // Panel 3: Process Analyzer
        JPanel processPanel = new JPanel(new BorderLayout());
        JButton processButton = createButton("Analyze Process Logs");
        JTextArea processLogArea = createTextArea();
        processPanel.add(processButton, BorderLayout.NORTH);
        processPanel.add(new JScrollPane(processLogArea), BorderLayout.CENTER);

        processButton.addActionListener(e -> {
            outputArea.append("[INFO] Analyzing process logs...\n");
            new Thread(() -> {
                try {
                    ProcessCreationAnalyzer.analyzeProcessCreationEvents("logs/security_event_log.xml", "logs/suspicious_process_events.json", processLogArea);
                    outputArea.append("[SUCCESS] Process analysis completed.\n");
                } catch (Exception ex) {
                    outputArea.append("[ERROR] Process analysis failed: " + ex.getMessage() + "\n");
                    ex.printStackTrace();
                }
            }).start();
        });

        // Panel 4: Report Generator
        JPanel reportPanel = new JPanel(new BorderLayout());
        JButton reportButton = createButton("Generate Final Report");
        JTextArea reportArea = createTextArea();
        reportPanel.add(reportButton, BorderLayout.NORTH);
        reportPanel.add(new JScrollPane(reportArea), BorderLayout.CENTER);

        reportButton.addActionListener(e -> {
            outputArea.append("[INFO] Generating final report...\n");
            new Thread(() -> {
                try {
                	String reportPath = ReportGenerator.generateReport("suspicious/suspicious_scan.json", "logs/suspicious_process_events.json", "logs/");

                    outputArea.append("[SUCCESS] Report generated: " + reportPath + "\n");

                    StringBuilder reportContent = new StringBuilder();
                    try (Scanner scanner = new Scanner(new File(reportPath))) {
                        while (scanner.hasNextLine()) {
                            reportContent.append(scanner.nextLine()).append("\n");
                        }
                    }
                    reportArea.setText(reportContent.toString());
                } catch (Exception ex) {
                    outputArea.append("[ERROR] Report generation failed: " + ex.getMessage() + "\n");
                    ex.printStackTrace();
                }
            }).start();
        });
        
     // Panel 5: Baseline Generator
        JPanel baselinePanel = new JPanel(new BorderLayout());
        JButton baselineButton = createButton("Generate Baseline");
        JTextArea baselineArea = createTextArea();
        baselinePanel.add(baselineButton, BorderLayout.NORTH);
        baselinePanel.add(new JScrollPane(baselineArea), BorderLayout.CENTER);

        // Baseline generation logic
        baselineButton.addActionListener(e -> {
            outputArea.append("[INFO] Starting baseline generation...\n");
            new Thread(() -> {
                try {
                    String baselineDir = "baseline/"; // Change if needed
                    String outputPath = "baseline/baseline.json";

                    File folder = new File(baselineDir);
                    if (!folder.exists() || Objects.requireNonNull(folder.listFiles()).length == 0) {
                        outputArea.append("[WARNING] Baseline directory is empty or missing.\n");
                        baselineArea.setText("Baseline directory is empty or does not exist.");
                        return;
                    }

                    BaselineGenerator.generateBaseline(baselineDir, outputPath);
                    outputArea.append("[SUCCESS] Baseline generated at: " + outputPath + "\n");

                    StringBuilder fileList = new StringBuilder("Baseline Generated:\n\n");
                    for (File file : Objects.requireNonNull(folder.listFiles())) {
                        if (file.isFile()) {
                            fileList.append("File: ").append(file.getName()).append("\n");
                        }
                    }
                    baselineArea.setText(fileList.toString());
                } catch (Exception ex) {
                    outputArea.append("[ERROR] Failed to generate baseline: " + ex.getMessage() + "\n");
                    baselineArea.setText("Error occurred: " + ex.getMessage());
                    ex.printStackTrace();
                }
            }).start();
        });


        // Add tabs
        tabbedPane.addTab("Resource Monitor", resourcePanel);
        tabbedPane.addTab("Baseline Generator", baselinePanel);
        tabbedPane.addTab("Suspicious File Scan", fileScanPanel);
        tabbedPane.addTab("Process Analyzer", processPanel);
        tabbedPane.addTab("Report Generator", reportPanel);

        // Output/log area
        outputArea = createTextArea();
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputScroll.setPreferredSize(new Dimension(1000, 150));

        frame.add(tabbedPane, BorderLayout.CENTER);
        frame.add(outputScroll, BorderLayout.SOUTH);
        frame.setVisible(true);
    }

    private static JButton createButton(String text) {
        JButton button = new JButton(text);
        button.setFocusPainted(false);
        button.setBackground(new Color(60, 63, 65));
        button.setForeground(Color.WHITE);
        button.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        button.setBorder(BorderFactory.createEmptyBorder(5, 15, 5, 15));
        return button;
    }

    private static JTextArea createTextArea() {
        JTextArea area = new JTextArea(10, 80);
        area.setEditable(false);
        area.setBackground(new Color(30, 32, 34));
        area.setForeground(Color.WHITE);
        area.setCaretColor(Color.WHITE);
        area.setFont(new Font("Consolas", Font.PLAIN, 13));
        return area;
    }
}
