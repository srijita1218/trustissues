from agent.collectors.process_monitor import monitor_processes


def main():
    print("Starting process monitor...")
    print("Open an application to generate a process event.")
    print()

    for process in monitor_processes(interval=2):
        print("NEW PROCESS DETECTED")
        print(process)
        print("-" * 80)


if __name__ == "__main__":
    main()