def calculate_risk(alerts):

    if len(alerts) == 0:
        return "LOW"

    elif len(alerts) <= 2:
        return "MEDIUM"

    elif len(alerts) <= 4:
        return "HIGH"

    return "CRITICAL"