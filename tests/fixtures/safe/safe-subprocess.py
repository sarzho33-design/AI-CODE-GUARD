# Safe fixture — must NOT trigger any findings. Used to catch false positives.
import subprocess

def resize_image(filename: str) -> None:
    # Args passed as a list, no shell=True — no shell interpolation risk.
    subprocess.run(["convert", filename, "-resize", "50%", "output.png"], check=True)
