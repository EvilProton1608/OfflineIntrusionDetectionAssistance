package monitoring1;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.json.JSONObject;

import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HWDiskStore;
import oshi.software.os.OSProcess;
import oshi.software.os.OperatingSystem;

public class SystemResourceMonitor {

    private static final double CPU_THRESHOLD = 0.65; // 65%
    private static final long DISK_IO_THRESHOLD = 50 * 1024 * 1024; // 50 MB/s

    public static void startMonitoring() {
        SystemInfo systemInfo = new SystemInfo();
        CentralProcessor processor = systemInfo.getHardware().getProcessor();
        GlobalMemory memory = systemInfo.getHardware().getMemory();
        List<HWDiskStore> diskStores = systemInfo.getHardware().getDiskStores();

        // Capture CPU ticks
        long[] prevTicks = processor.getSystemCpuLoadTicks();

        // Capture disk I/O before sleep
        long diskReadBefore = 0;
        long diskWriteBefore = 0;
        for (HWDiskStore disk : diskStores) {
            disk.updateAttributes();
            diskReadBefore += disk.getReadBytes();
            diskWriteBefore += disk.getWriteBytes();
        }

        try {
            Thread.sleep(1000); // 1 second delay
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        double cpuLoad = processor.getSystemCpuLoadBetweenTicks(prevTicks);
        long totalMemory = memory.getTotal();
        long availableMemory = memory.getAvailable();
        long usedMemory = totalMemory - availableMemory;

        // Disk I/O after 1 second
        long diskReadAfter = 0;
        long diskWriteAfter = 0;
        for (HWDiskStore disk : diskStores) {
            disk.updateAttributes();
            diskReadAfter += disk.getReadBytes();
            diskWriteAfter += disk.getWriteBytes();
        }

        long diskReadPerSec = diskReadAfter - diskReadBefore;
        long diskWritePerSec = diskWriteAfter - diskWriteBefore;

        boolean highCpuUsage = cpuLoad > CPU_THRESHOLD;
        boolean highDiskIO = (diskReadPerSec + diskWritePerSec) > DISK_IO_THRESHOLD;

        JSONObject logEntry = new JSONObject();
        logEntry.put("timestamp", LocalDateTime.now().toString());
        logEntry.put("cpuLoadPercent", String.format("%.2f", cpuLoad * 100));
        logEntry.put("cpuHighUsage", highCpuUsage);
        logEntry.put("totalMemory", totalMemory);
        logEntry.put("availableMemory", availableMemory);
        logEntry.put("usedMemory", usedMemory);
        logEntry.put("diskReadBps", diskReadPerSec);
        logEntry.put("diskWriteBps", diskWritePerSec);
        logEntry.put("diskIOSpike", highDiskIO);

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

        return String.format(
            "[%s] CPU: %.2f%% | Used: %.2f GB / %.2f GB",
            java.time.LocalTime.now().withNano(0),
            cpuLoad * 100,
            usedMemory / 1e9,
            totalMemory / 1e9
        );
    }

    public static List<OSProcess> getHighMemoryProcesses(long thresholdMB) {
        SystemInfo si = new SystemInfo();
        OperatingSystem os = si.getOperatingSystem();

        return os.getProcesses().stream()
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
