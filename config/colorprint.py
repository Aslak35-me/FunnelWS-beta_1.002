from colorama import Fore, Style
import os
import time


current_os = platform.system()
os.system('cls' if current_os == "Windows" else 'clear')

logo = r"""
+----------------------------------------------------+
|                                                    |
|                                                    |
|   _____                       ___        ______    |
|  |  ___|   _ ____  ____   ___| \ \      / / ___|   |
|  | |_ | | | | __ \| __ \ / _ \ |\ \ /\ / /\___ \   |
|  |  _|| |_| | | | | | | |  __/ | \ V  V /  ___) |  |
|  |_|   \____|_| |_|_| |_|\___|_|  \_/\_/  |____/   |
|                                                    |
|                                                    |
+----------------------------------------------------+
"""

print(Fore.RED + logo + Fore.RESET)
print("[*]\tFunnelWS Web Vulnerability Scanner")
print("[*]\tFunnelWS Version BETA_1.002\n")
print("======================================================\n")


