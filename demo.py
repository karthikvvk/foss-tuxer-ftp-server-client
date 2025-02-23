#!/usr/bin/env python3
import subprocess
import os
import sys
import pwd
from pathlib import Path

class FTPServerSetup:
    def __init__(self):
        # Check if running as root
        if os.geteuid() != 0:
            print("Please run as root")
            sys.exit(1)

    def run_command(self, command, shell=False):
        """Execute a command and return its output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, check=True, 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
            else:
                result = subprocess.run(command.split(), check=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {command}")
            print(f"Error message: {e.stderr}")
            return None

    def user_exists(self, username):
        """Check if a user exists"""
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            return False

    def configure_firewall(self):
        """Configure UFW firewall rules"""
        print("Configuring firewall rules...")
        rules = [
            "ufw allow 20/tcp",
            "ufw allow 21/tcp",
            "ufw allow 990/tcp",
            "ufw allow 5000:10000/tcp"
        ]
        for rule in rules:
            self.run_command(rule)

    def setup_ftp_user(self):
        """Create FTP user if not exists"""
        if not self.user_exists("ftpuser"):
            print("Creating ftpuser...")
            self.run_command("adduser --gecos '' ftpuser")
        else:
            print("ftpuser already exists")

    def configure_ssh(self):
        """Configure SSH settings"""
        print("Configuring SSH...")
        sshd_config = Path("/etc/ssh/sshd_config")
        
        # Read existing config
        with open(sshd_config, 'r') as f:
            config_content = f.read()

        # Add DenyUsers if not present
        if "DenyUsers ftpuser" not in config_content:
            with open(sshd_config, 'a') as f:
                f.write("\nDenyUsers ftpuser\n")

        self.run_command("systemctl restart sshd")

    def setup_ftp_directory(self):
        """Create and configure FTP directory"""
        print("Setting up FTP directory...")
        ftp_dir = Path("/ftp")
        ftp_dir.mkdir(exist_ok=True)
        self.run_command(f"chown ftpuser:ftpuser {ftp_dir}")
        self.run_command(f"chmod 755 {ftp_dir}")

    def generate_ssl_cert(self):
        """Generate SSL certificate"""
        print("Generating SSL certificate...")
        ssl_cmd = (
            "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
            "-keyout /etc/ssl/private/vsftpd.pem "
            "-out /etc/ssl/private/vsftpd.pem "
            "-subj '/C=IN/ST=Delhi/O=my/OU=main/CN=myftp/emailAddress=ftpuser@gmail.com'"
        )
        self.run_command(ssl_cmd, shell=True)

    def configure_vsftpd(self):
        """Configure VSFTPD"""
        print("Configuring VSFTPD...")
        config_content = """# Default configuration
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=0002
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd

# Custom configuration
pasv_min_port=5000
pasv_max_port=10000
local_root=/ftp
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
allow_writeable_chroot=YES

# SSL Configuration
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
"""
        # Write vsftpd configuration
        with open('/etc/vsftpd.conf', 'w') as f:
            f.write(config_content)

        # Create and populate chroot list
        with open('/etc/vsftpd.chroot_list', 'w') as f:
            f.write("ftpuser\n")

    def install_packages(self):
        """Install required packages"""
        print("Installing required packages...")
        self.run_command("apt-get update")
        self.run_command("apt-get install -y vsftpd ufw openssl")

    def setup(self):
        """Main setup method"""
        print("Starting FTP server configuration...")
        
        self.install_packages()
        self.configure_firewall()
        self.setup_ftp_user()
        self.configure_ssh()
        self.setup_ftp_directory()
        self.generate_ssl_cert()
        self.configure_vsftpd()

        # Restart and enable VSFTPD service
        print("Restarting VSFTPD service...")
        self.run_command("systemctl restart vsftpd")
        self.run_command("systemctl enable vsftpd")

        print("\nFTP server configuration completed!")
        print("Please ensure to remember the password you set for ftpuser")
        print("FTP server is now ready to use with SSL/TLS enabled")

if __name__ == "__main__":
    ftp_setup = FTPServerSetup()
    ftp_setup.setup()