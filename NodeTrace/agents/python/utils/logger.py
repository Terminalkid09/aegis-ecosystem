import datetime

class Logger:
    @staticmethod
    def info(msg):
        print(f"\033[96m[{datetime.datetime.now()}] [INFO] {msg}\033[0m")

    @staticmethod
    def warn(msg):
        print(f"\033[93m[{datetime.datetime.now()}] [WARN] {msg}\033[0m")

    @staticmethod
    def error(msg):
        print(f"\033[91m[{datetime.datetime.now()}] [ERROR] {msg}\033[0m")