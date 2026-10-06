from agent.collectors.process_monitor import monitor_processes
from agent.pipeline.normalizer import normalize_process
from database.event_store import initialize_database, save_event


def main():
    initialize_database()

    print("========================================")
    print("        trustIssues Endpoint Agent")
    print("========================================")
    print()
    print("Monitoring process activity...")
    print()

    for process in monitor_processes(interval=2):
        event = normalize_process(process)

        save_event(event)

        print(
            f"[PROCESS CREATED] "
            f"{event.process_name} "
            f"(PID={event.process_id}, "
            f"PPID={event.parent_process_id})"
        )


if __name__ == "__main__":
    main()