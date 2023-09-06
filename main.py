import os
import re
import sys
import time
import logging
import pytz
from pyinotify import WatchManager, Notifier, EventsCodes, ProcessEvent
from termcolor import colored
from datetime import datetime

log_file_path = '/var/log/psono_ee/audit.log'
eol = '=' * 60 + '\n'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)


def get_event_type(log_line):
    event_type_pattern = r'event=(\w+)'
    event_type_match = re.search(event_type_pattern, log_line)
    if event_type_match:
        return event_type_match.group(1)
    else:
        return None


def format_date(input_date):
    try:
        input_datetime = datetime.strptime(input_date, "%Y-%m-%dT%H:%M:%S.%f")
        paris_timezone = pytz.timezone('Europe/Paris')
        input_datetime_paris = input_datetime.replace(tzinfo=pytz.utc).astimezone(paris_timezone)
        formatted_date = input_datetime_paris.strftime("%d/%m/%Y %H:%M:%S")
        return formatted_date
    except ValueError:
        return None


def parse_log_line(log_line):
    patterns = [
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+)$', []),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+)$', ["user", "user_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_secret_id=([\w\d-]+)$', ["user", "user_id", "kwarg_secret_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_datastore_id=([\w\d-]+)$', ["user", "user_id", "kwarg_datastore_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_link_share_id=([\w\d-]+)$', ["user", "user_id", "kwarg_link_share_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), errors=([^,]+), user=([^,]+), user_id=([\w\d-]+)$', ["errors", "user", "user_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_security_report_id=([\w\d-]+)$', ["user", "user_id", "kwarg_security_report_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_token_id=([\w\d-]+)$', ["user", "user_id", "kwarg_token_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_administrated_user_id=([\w\d-]+)$', ["user", "user_id", "kwarg_administrated_user_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_secret_link_id=([\w\d-]+)$', ["user", "user_id", "kwarg_secret_link_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_group_id=([\w\d-]+)$', ["user", "user_id", "kwarg_group_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_ldap_group_map_id=([\w\d-]+)$', ["user", "user_id", "kwarg_ldap_group_map_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_membership_id=([\w\d-]+), kwarg_group_id=([\w\d-]+)$', ["user", "user_id", "kwarg_membership_id", "kwarg_group_id"]),
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) logger=([^,]*), user_ip=(\d+\.\d+\.\d+\.\d+), req_method=(\w+), req_url=([^,]+), success=(\w+), hostname=([\w\d]+), status=(\w+), event=(\w+), user=([^,]+), user_id=([\w\d-]+), kwarg_membership_id=([\w\d-]+), kwarg_group_id=([\w\d-]+), kwarg_group_name=([\w\d-]+), kwarg_membership_user_id=([\w\d-]+), kwarg_membership_user_name=([^,]+)$', ["user", "user_id", "kwarg_membership_id", "kwarg_group_id", "kwarg_group_name", "kwarg_membership_user_id", "kwarg_membership_user_name"])
    ]

    for pattern, extra_fields in patterns:
        match = re.match(pattern, log_line)
        if match:
            groups = match.groups()
            log_data = dict(zip(["timestamp", "logger", "user_ip", "req_method", "req_url", "success", "hostname", "status", "event"], groups))
            for field in extra_fields:
                log_data[field] = groups[len(log_data)]
            log_data['timestamp'] = format_date(log_data['timestamp'])
            return log_data

    print(colored(f"Could not parse log line: {log_line}", 'red'))
    return None


class EventHandler(ProcessEvent):
    def __init__(self):
        self.log_file_position = os.path.getsize(log_file_path)

    def process_IN_MODIFY(self, event):
        if event.pathname == log_file_path:
            with open(log_file_path, 'r') as log_file:
                log_file.seek(self.log_file_position)
                new_lines = log_file.readlines()
                for line in new_lines:
                    print(colored("Line Detected : {}".format(get_event_type(line)), 'yellow'))
                    log_data = parse_log_line(line.strip())
                    if log_data:
                        for key, value in log_data.items():
                            print(colored(f"{key}: {value}", 'cyan'))
                    print(eol)
                self.log_file_position = log_file.tell()


def main():
    print(colored("Psono Logging Audit Tool", 'green'))
    wm = WatchManager()
    mask = EventsCodes.FLAG_COLLECTIONS['OP_FLAGS']['IN_MODIFY']
    notifier = Notifier(wm, EventHandler())
    wm.add_watch(log_file_path, mask)

    try:
        while True:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
    except KeyboardInterrupt:
        notifier.stop()


if __name__ == "__main__":
    main()
