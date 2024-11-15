# Windows Event Forensics

## Description

Windows Event Forensics is a Python-based tool designed to assist forensic investigators and cybersecurity professionals in analyzing and monitoring Windows security event logs. This tool helps detect unusual activities, identify potential security incidents, and provides valuable insights for forensic analysis by calculating risk scores based on event severity and generating detailed daily reports.

## Features:

- Security Event Log Forensics: Retrieves and processes Windows security event logs for forensic analysis.
- Risk Scoring: Assigns risk scores based on the severity of events and generates an overall daily score to highlight potential security incidents.
- Event Frequency Analysis: Tracks the most frequent events, which may indicate unusual or malicious activity.
- Customizable Event Severity Mapping: Supports modification of event IDs and their severity levels to suit specific needs.
- Daily Forensic Report Generation: Automatically generates and logs a daily report summarizing the most significant events for forensic review.
- Logging and Error Handling: Logs all actions and captures errors for troubleshooting and audit purposes.

## Supported Event IDs:

The tool currently supports the following Event IDs, which are commonly associated with security-related activities:

- 4670: Permissions on an object were changed
- 1102: Audit log cleared
- 5156: Windows Filtering Platform allowed a connection
- 5158: Windows Filtering Platform blocked a connection
- 4720: A user account was created
- 4726: A user account was deleted

## Installation:

1. Clone this repository:

```bash
git clone https://github.com/SushantAzad/windows-event-forensics.git
```

2. Install dependencies: Ensure Python is installed and then install the required packages:

```bash
pip install pywin32
```

3. Run the script: To start analyzing the event logs, run the event_log_forensics.py script:

```bash
python event_log_forensics.py
```

## Result Code Example:

When you run the script, it generates daily security reports based on the analyzed Windows event logs. Here's an example of what the output might look like:

```bash
2024-11-15 22:45:39 INFO: Opening Security event log...
2024-11-15 22:45:40 INFO: No more events found.
2024-11-15 22:45:40 INFO: Generating daily security report...

Daily Security Report:
Date: 2024-11-15, Total Score: 63, Risk Level: high
   Most Frequent Event: ID 4720 (A user account was created) (Occurred 21 times)
Date: 2024-11-14, Total Score: 18, Risk Level: low
   Most Frequent Event: ID 5156 (Windows Filtering Platform has allowed a connection) (Occurred 6 times)
```

This shows the date, total score, risk level, and the most frequent event for each day. The most frequent event is associated with its Event ID and description.

## Risk Levels and Range:

The risk level is determined based on the total score calculated from the severity of events occurring each day. The risk level helps identify potential security risks by categorizing the overall score into different levels.

### Risk Level Mapping:

- Low: Score between 0 and 50
- Medium: Score between 51 and 150
- High: Score greater than 150
- Zero: A score of 0, indicating no unusual activities detected.

## Logging:

All actions and errors are logged to `security_event_log_forensics.log`. Make sure to review the log file for detailed forensic analysis and troubleshooting.
