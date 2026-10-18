import math

def sort_alerts(alerts):
    return sorted(alerts, key=lambda x: -x[1])


def is_blocked(blocklist, ip):
    return ip in blocklist


def find_signature(log, pattern):
    hits = []
    start = 0

    if pattern == "":
        return list(range(len(log) + 1))

    while True:
        pos = log.find(pattern, start)

        if pos == -1:
            break

        hits.append(pos)
        start = pos + 1

    return hits


def closest_logins(events):
    n = len(events)

    if n < 2:
        return None, float("inf")

    points = sorted(
        [(x, y, i) for i, (x, y) in enumerate(events)]
    )

    min_dist_sq = float("inf")
    pair = None

    for i in range(n):
        x1, y1, index1 = points[i]

        for j in range(i + 1, n):
            x2, y2, index2 = points[j]
            dx = x2 - x1

            if dx * dx >= min_dist_sq:
                break

            dy = y2 - y1
            dist_sq = dx * dx + dy * dy

            if dist_sq < min_dist_sq:
                min_dist_sq = dist_sq
                pair = (index1, index2)

    return pair, math.sqrt(min_dist_sq)



alerts = [
    ("A1", 3), ("A2", 9), ("A3", 5),
    ("A4", 9), ("A5", 1)
]

blocklist = ["10.0.0.5", "192.168.1.2"]

queries = ["10.0.0.5", "8.8.8.8"]

log = "FAILFAKEFAIL"
pattern = "FAIL"

events = [
    (2, 3), (12, 30), (40, 50),
    (5, 1), (12, 10), (3, 4)
]

print("Sorted alerts:", sort_alerts(alerts))

for ip in queries:
    print(ip, ":", is_blocked(blocklist, ip))

print("Signature positions:", find_signature(log, pattern))

pair, distance = closest_logins(events)
print("Closest pair:", pair)
print("Minimum distance:", round(distance, 4))
