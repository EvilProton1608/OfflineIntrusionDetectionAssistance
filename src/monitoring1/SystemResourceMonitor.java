package monitoring1;

import oshi.SystemInfo;
import oshi.hardware.GlobalMemory;
import oshi.hardware.CentralProcessor;
import oshi.software.os.OSProcess;
import oshi.software.os.OperatingSystem;


import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

public class SystemResourceMonitor {
	public static void startMonitoring() {
	    SystemInfo systemInfo = new SystemInfo();
	    CentralProcessor processor = systemInfo.getHardware().getProcessor();
	    GlobalMemory memory = systemInfo.getHardware().getMemory();

	    long[] prevTicks = processor.getSystemCpuLoadTicks();
	    try {
	        Thread.sleep(1000);
	    } catch (InterruptedException e) {
	        e.printStackTrace();
	    }

	    double cpuLoad = processor.getSystemCpuLoadBetweenTicks(prevTicks);
	    long totalMemory = memory.getTotal();
	    long availableMemory = memory.getAvailable();
	    long usedMemory = totalMemory - availableMemory;

	    JSONObject logEntry = new JSONObject();
	    logEntry.put("timestamp", LocalDateTime.now().toString());
	    logEntry.put("cpuLoadPercent", String.format("%.2f", cpuLoad * 100));
	    logEntry.put("totalMemory", totalMemory);
	    logEntry.put("availableMemory", availableMemory);
	    logEntry.put("usedMemory", usedMemory);

	    try (FileWriter file = new FileWriter("logs/system_resource_log.json", true)) {
	        file.write(logEntry.toString() + System.lineSeparator());
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	}

    public static String captureSnapshot() {
        SystemInfo systemInfo = new SystemInfo();
        CentralProcessor processor = systemInfo.getHardware().getProcessor();
        GlobalMemory memory = systemInfo.getHardware().getMemory();

        long[] prevTicks = processor.getSystemCpuLoadTicks();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        double cpuLoad = processor.getSystemCpuLoadBetweenTicks(prevTicks);
        long totalMemory = memory.getTotal();
        long availableMemory = memory.getAvailable();
        long usedMemory = totalMemory - availableMemory;

        String log = String.format(
            "[%s] CPU: %.2f%% | Used: %.2f GB / %.2f GB",
            java.time.LocalTime.now().withNano(0),
            cpuLoad * 100,
            usedMemory / 1e9,
            totalMemory / 1e9
        );

        return log;
    }
    public static List<OSProcess> getHighMemoryProcesses(long thresholdMB) {
        SystemInfo si = new SystemInfo();
        OperatingSystem os = si.getOperatingSystem();

        List<OSProcess> allProcesses = os.getProcesses();  // No ProcessSort in 6.8.2

        return allProcesses.stream()
            .filter(p -> p.getResidentSetSize() / (1024 * 1024) > thresholdMB)
            .collect(Collectors.toList());
    }

    public static String formatProcess(OSProcess p) {
        return String.format("PID: %d | Name: %s | RAM: %.2f MB | CPU: %.2f%%",
                p.getProcessID(),
                p.getName(),
                p.getResidentSetSize() / 1e6,
                100d * p.getProcessCpuLoadCumulative());
    }


}
