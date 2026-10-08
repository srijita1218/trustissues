from agent.models.security_event import SecurityEvent


def suspicious_execution_path(event: SecurityEvent):
    if not event.executable_path:
        return False

    suspicious_locations = [
        "\\AppData\\Local\\Temp\\",
        "\\AppData\\Roaming\\",
        "\\Temp\\",
    ]

    executable_path = event.executable_path.lower()

    for location in suspicious_locations:
        if location.lower() in executable_path:
            return True

    return False


def suspicious_parent(event: SecurityEvent):
    suspicious_parents = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
    }

    parent_name = event.metadata.get("parent_process_name")

    if not parent_name:
        return False

    return parent_name.lower() in suspicious_parents


def suspicious_command_line(event: SecurityEvent):
    command_line = event.metadata.get("command_line")

    if not command_line:
        return False

    suspicious_terms = [
        "-encodedcommand",
        "downloadstring",
        "invoke-expression",
        "bypass",
    ]

    if isinstance(command_line, list):
        command_text = " ".join(command_line).lower()
    else:
        command_text = command_line.lower()
        
    return any(term in command_text for term in suspicious_terms)
