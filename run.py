from core.firewall import start_firewall
from ui.app import app
import threading

# Start firewall simulation in background thread
threading.Thread(target=start_firewall, args=("sim",), daemon=True).start()

# Start Flask
app.run(port=5000, debug=True)