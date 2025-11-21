# smtp_server.py
import os
import datetime
import time
from aiosmtpd.controller import Controller

OUT_DIR = "messages"
os.makedirs(OUT_DIR, exist_ok=True)

class SaveMessageHandler:
    async def handle_DATA(self, server, session, envelope):
        now = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        filename = os.path.join(OUT_DIR, f"msg_{now}.eml")
        with open(filename, "wb") as f:
            f.write(envelope.original_content)  # exact raw bytes
        print(f"Saved: {filename}")
        return "250 Message accepted for delivery"

def run_server(host="127.0.0.1", port=1025):
    controller = Controller(SaveMessageHandler(), hostname=host, port=port)
    controller.start()
    print(f"Listening on {host}:{port} — messages -> ./messages/")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("Shutting down server.")
    finally:
        controller.stop()

if __name__ == "__main__":
    run_server()
