import os
import datetime
import logging
import win32evtlog

# Configure logging
logging.basicConfig(
    filename='security_event_log_analyzer.log',
    level=logging.DEBUG,  # Change to DEBUG for more detailed logs
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Event ID to severity mapping (Updated)
event_severity = {
    4670: 4,  # Permissions on an object were changed
    1102: 10,  # Audit log cleared
    5156: 5,  # Windows Filtering Platform has allowed a connection
    5158: 5,  # Windows Filtering Platform has blocked a connection
    4720: 3,  # A user account was created
    4726: 3,  # A user account was deleted
}

# Event descriptions for Event IDs (Updated)
event_descriptions = {
    4670: "Permissions on an object were changed",
    1102: "Audit log cleared",
    5156: "Windows Filtering Platform has allowed a connection",
    5158: "Windows Filtering Platform has blocked a connection",
    4720: "A user account was created",
    4726: "A user account was deleted",
}

# Thresholds for risk levels (Updated to a higher range)
risk_thresholds = {
    'zero': 0,
    'low': 50,
    'medium': 150,
    'high': 151
}

def analyze_security_logs():
    """
    Analyze Windows security event logs and generate reports.
    """
    daily_scores = {}
    daily_event_counts = {}
    
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    try:
        print("Opening Security event log...")
        logging.info("Opening Security event log...")
        hand = win32evtlog.OpenEventLog(server, log_type)
        
        event_found = False  # Flag to track if any events were found
        
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                logging.info("No more events found.")
                break
            
            for event in events:
                event_id = event.EventID & 0xFFFF
                if event_id in event_severity:
                    score = event_severity[event_id]
                    time_generated = event.TimeGenerated
                    
                    # Update daily scores
                    date = time_generated.date()
                    if date not in daily_scores:
                        daily_scores[date] = 0
                        daily_event_counts[date] = {}
                    daily_scores[date] += score
                    
                    # Count the event occurrences
                    if event_id not in daily_event_counts[date]:
                        daily_event_counts[date][event_id] = 0
                    daily_event_counts[date][event_id] += 1
                    
                    logging.debug(f"Event ID {event_id} detected at {time_generated}, score: {score}")
                    event_found = True  # Set flag to True when at least one event is found
        
    except Exception as e:
        logging.error(f"Error: {str(e)}")
    finally:
        if 'hand' in locals() and hand:
            win32evtlog.CloseEventLog(hand)
    
    # Generate reports
    if event_found:
        generate_daily_report(daily_scores, daily_event_counts)
    else:
        print("\nDaily Security Report: \nNo unusual activities detected.")
        logging.info("No events found. No unusual activities detected.")

def generate_daily_report(daily_scores, daily_event_counts):
    print("\nDaily Security Report:")
    logging.info("Generating daily security report...")
    for date, score in daily_scores.items():
        risk_level = get_risk_level(score)
        # Find the most frequent event for the day
        most_frequent_event = max(daily_event_counts[date], key=daily_event_counts[date].get)
        event_count = daily_event_counts[date][most_frequent_event]
        
        # Fetch the event description
        event_description = event_descriptions.get(
            most_frequent_event, f"No description available for ID {most_frequent_event}"
        )
        
        # Print the daily report with descriptions
        print(f"Date: {date}, Total Score: {score}, Risk Level: {risk_level}")
        print(f"   Most Frequent Event: ID {most_frequent_event} "
              f"({event_description}) (Occurred {event_count} times)")
        logging.info(f"Daily report for {date}: Total score {score}, Risk level: {risk_level}, "
                     f"Most frequent event: ID {most_frequent_event} ({event_description}), Count: {event_count}")

def get_risk_level(score):
    """
    Determine the risk level based on the provided score.
    """
    if score == 0:
        return 'zero'
    elif score <= risk_thresholds['low']:
        return 'low'
    elif score <= risk_thresholds['medium']:
        return 'medium'
    else:
        return 'high'

if __name__ == "__main__":
    analyze_security_logs()
