import os
import multiprocessing

port = os.environ.get("PORT", "5001")
bind = f"0.0.0.0:{port}"
workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
worker_class = "sync"
timeout = 120
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
