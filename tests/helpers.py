import random

from linuxguard.detection.anomaly.windows import ActivityWindow
from linuxguard.domain.events import EventCategory


def routine_windows(make_event, count=400, seed=3):
    rng = random.Random(seed)
    windows = []
    for index in range(count):
        start = 1_700_000_000 + index * 60 + 9 * 3600
        events = [
            make_event(
                timestamp=start + offset,
                executable=rng.choice(["/usr/bin/ls", "/usr/bin/git", "/usr/bin/cat", "/usr/bin/vim.basic"]),
                session_id=str(index % 5),
                auid=1001,
            )
            for offset in range(rng.randint(1, 6))
        ]
        if rng.random() < 0.2:
            events.append(
                make_event(
                    timestamp=start + 30,
                    category=EventCategory.NETWORK_CONNECTION,
                    dest_ip="140.82.112.3",
                    dest_port=443,
                    session_id=str(index % 5),
                    auid=1001,
                )
            )
        windows.append(ActivityWindow(f"alice@session:{index % 5}", start, start + 60, events))
    return windows


def scan_window(make_event):
    start = 1_700_000_000 + 10 * 3600
    events = [
        make_event(
            timestamp=start + index * 0.5,
            category=EventCategory.NETWORK_CONNECTION,
            dest_ip=f"10.0.0.{index}",
            dest_port=22,
            session_id="99",
            auid=1001,
        )
        for index in range(1, 80)
    ]
    return ActivityWindow("alice@session:99", start, start + 60, events)
