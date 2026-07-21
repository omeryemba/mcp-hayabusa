import os

HAYABUSA_DIR = r"C:\Users\omery\tools\hayabusa"

if HAYABUSA_DIR not in os.environ.get("PATH", ""):
    os.environ["PATH"] = HAYABUSA_DIR + os.pathsep + os.environ.get("PATH", "")
