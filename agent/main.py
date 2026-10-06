from agent.collectors.process_collector import collect_processes
from agent.pipeline.normalizer import normalize_process
from database.event_store import initialize_database, save_event


def main():
    initialize_database()

    processes = collect_processes()

    print(f"Collected {len(processes)} processes.\n")

    for process in processes:
        event = normalize_process(process)
        save_event(event)

    print("Events saved successfully.")


if __name__ == "__main__":
    main()