import time

import psutil


def get_running_processes():
    processes = {}

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "exe",
            "username",
            "create_time",
            "cpu_percent",
            "memory_percent",
            "cmdline",
        ]
    ):
        try:
            processes[process.info["pid"]] = process.info

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def monitor_processes(interval=2):
    previous_processes = get_running_processes()

    print(
        f"Monitoring {len(previous_processes)} running processes..."
    )

    while True:
        time.sleep(interval)

        current_processes = get_running_processes()

        new_pids = set(current_processes) - set(previous_processes)

        for pid in new_pids:
            yield current_processes[pid]

        previous_processes = current_processes