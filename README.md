# Offline Intrusion Detection Assistance

OfflineIntrusionDetectionAssistance is a Java project that performs basic, offline security analysis over local log/files and produces reports.

It includes:
- A CLI-style pipeline entrypoint: `app.Main`
- A UI entrypoint: `ui.MainDashboard`

## Prerequisites

- Windows (project uses Windows Security Event Log XML input by default)
- Java JDK (so `javac` and `java` are on PATH)
- PowerShell

> Note: The code references OSHI (`oshi.*`). If you don’t have the required JARs in the repo root, compilation will fail. Place any required dependency JARs in the repository root so `build.ps1` can pick them up.

## Quick start

### Build (compiles all sources)

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

By default, `build.ps1` compiles into `bin/` and runs the UI main class (`ui.MainDashboard`).

To build+run a specific main class:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 -MainClass app.Main
```

### Run (without recompiling)

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

To run the CLI pipeline:

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1 -MainClass app.Main
```

If `bin/` does not exist, `run.ps1` will invoke `build.ps1` once.

## What the CLI pipeline does (`app.Main`)

The default pipeline in `app.Main`:

1. Generates a baseline hash set into `baseline/baseline.json`
2. Parses a Windows Security Event Log XML file from `logs/security_event_log.xml` into `logs/security_event_log.json`
3. Analyzes process creation events and writes `logs/suspicious_process_events.json`
4. Scans the `suspicious/` folder and writes:
   - `suspicious/suspicious_scan.txt`
   - `suspicious/suspicious_scan.json`
5. Generates a report into `reports/` (timestamped)

It also starts a background thread that periodically logs high-memory processes to `logs/high_memory_processes.log`.

## Inputs and outputs

### Inputs

- `logs/security_event_log.xml` (Windows Security Event Log exported to XML)
- `suspicious/` (files to scan)
- `baseline/` (baseline storage)

### Outputs

- `baseline/baseline.json`
- `logs/security_event_log.json`
- `logs/suspicious_process_events.json`
- `logs/high_memory_processes.log`
- `suspicious/suspicious_scan.txt`, `suspicious/suspicious_scan.json`
- `reports/report_YYYYMMDD_HHMMSS.(json|txt)`

## Project layout

- `src/` Java sources
- `bin/` compiled classes output (created by build)
- `baseline/` baseline artifacts
- `logs/` log inputs and generated artifacts
- `suspicious/` files and scan results
- `reports/` generated reports

## Troubleshooting

- **`javac` not found**: install a JDK and ensure `JAVA_HOME`/PATH includes `bin`.
- **Missing dependencies (e.g., OSHI)**: put the required `*.jar` files in the repo root; scripts build the classpath from root-level jars.
- **No reports generated**: confirm `logs/security_event_log.xml` exists and is readable, and the `suspicious/` folder contains files to scan.
