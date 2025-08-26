import psutil
import time
import logging

THRESHOLD = 3
SECONDS = 10

vals = []

logging.basicConfig(
    filename='cpu_monitor.log',  
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info(f"Live monitoring started with threshold {THRESHOLD}% over {SECONDS} seconds")

while True:
    # print(f"this is the cpu-time{psutil.cpu_times_percent(interval=1)}")
    # print(f"this is the cpu %{psutil.cpu_percent(interval=1)}")
    vals.append(psutil.cpu_percent(interval=1))

    if len(vals) > SECONDS:
        vals.pop(0)
    if len(vals) == SECONDS:
        avg = sum(vals)/SECONDS
        logging.debug(f"Average CPU over last {SECONDS}s: {avg:.2f}%")
        if avg >= THRESHOLD:
            logging.warning(f"[ALERT] CPU usage {avg:.1f}% exceeded threshold over {SECONDS}s")
        vals.clear()