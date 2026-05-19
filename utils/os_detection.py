def detect_os(ttl):

    if ttl >= 120:
        return "Windows"

    elif ttl >= 60:
        return "Linux/Unix"

    return "Unknown"