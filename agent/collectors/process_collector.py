import psutil


def collect_processes():
    processes = []

    for process in psutil.process_iter(
        [
            "pid", #process id
            "ppid", #parent process id (important for attack-chain detection)
            "name",
            "exe",
            "username",
            "create_time",
            "cpu_percent",
            "memory_percent",
        ]
    ):
        try:
            information = process.info

            processes.append(information)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


if __name__ == "__main__":
    processes = collect_processes()

    for process in processes:
        print(process)