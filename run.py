from core.firewall import start_firewall
from threading import Thread
import os

def start_ui():
    os.system("python -m ui.app")

if __name__ == "__main__":
    Thread(target=start_ui).start()
    start_firewall(mode="sim")  # change to "real" on Linux