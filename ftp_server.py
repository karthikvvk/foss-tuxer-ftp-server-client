

from ftplib import FTP
import streamlit as st
import os
import subprocess
import requests

from pathlib import Path


def ensure_directory_exists(filepath):
    directory = os.path.dirname(filepath)
    if not os.path.exists(directory):
        os.makedirs(directory)





def apply_configuration(config_content, file_path):
    st.subheader("Administrator Permission Required")

    # Ask user for their sudo password
    sudo_password = st.text_input("Enter your sudo password:", type="password")

    if st.button("Apply Configuration"):
        if not sudo_password:
            st.error("❌ Password is required to proceed.")
            return

        try:
            # Use echo to pass the password to sudo
            command = f'echo {sudo_password} | sudo -S tee -a {file_path}'
            process = subprocess.run(command, input=config_content, text=True, shell=True, check=True)

            st.success(f"✅ Configuration applied successfully to {file_path}!")
        except subprocess.CalledProcessError as e:
            st.error(f"❌ Failed to apply configuration: {str(e)}")
            st.info("Make sure the password is correct and you have sudo privileges.")


def get_public_ip():
    try:
        response = requests.get('https://ifconfig.me')
        print(response.text)
        if response.status_code == 200:
            return response.text.strip()
        else:
            raise Exception(f"Failed to fetch IP: HTTP {response.status_code}")
    except Exception as e:
        st.error(f"Failed to fetch public IP: {str(e)}")
        return None

def server_control_panel():
    st.header("Server Control Panel")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Start Server"):
            try:
                subprocess.run(["systemctl", "start", "vsftpd"], check=True)
                if st.session_state.get('enable_ssh', False):
                    subprocess.run(["systemctl", "start", "sshd"], check=True)
                st.success("Server started successfully!")
            except subprocess.CalledProcessError as e:
                st.error(f"Failed to start server: {str(e)}")
    
    with col2:
        if st.button("Stop Server"):
            try:
                subprocess.run(["systemctl", "stop", "vsftpd"], check=True)
                if st.session_state.get('enable_ssh', False):
                    subprocess.run(["systemctl", "stop", "sshd"], check=True)
                st.success("Server stopped successfully!")
            except subprocess.CalledProcessError as e:
                st.error(f"Failed to stop server: {str(e)}")
    
    with col3:
        if st.button("Restart Server"):
            try:
                subprocess.run(["systemctl", "restart", "vsftpd"], check=True)
                if st.session_state.get('enable_ssh', False):
                    subprocess.run(["systemctl", "restart", "sshd"], check=True)
                st.success("Server restarted successfully!")
            except subprocess.CalledProcessError as e:
                st.error(f"Failed to restart server: {str(e)}")




import subprocess
import streamlit as st

def run_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        st.success(f"Command succeeded: {command}")
    else:
        st.error(f"Command failed: {command}\n{result.stderr}")

if st.button("Quick Server Hosting"):
    commands = [
        "sudo apt install -y vsftpd",
        "sudo systemctl enable --now vsftpd",
        "sudo ufw allow 20/tcp",
        "sudo ufw allow 21/tcp",
        "sudo ufw allow 990/tcp",
        "sudo ufw allow 5000:10000/tcp",
        "sudo adduser --disabled-password --gecos \"\" ftpuser",
        "echo 'ftpuser:2345' | sudo chpasswd",
        "sudo bash -c 'echo DenyUsers ftpuser >> /etc/ssh/sshd_config'",
        "sudo systemctl restart sshd",
        "sudo mkdir /ftp",
        "sudo chown ftpuser:ftpuser /ftp",
        "sudo bash -c 'cat <<EOF > /etc/vsftpd.conf\n\
anonymous_enable=NO\n\
local_enable=YES\n\
write_enable=YES\n\
pasv_min_port=5000\n\
pasv_max_port=10000\n\
local_root=/ftp\n\
chroot_local_user=YES\n\
chroot_list_enable=YES\n\
chroot_list_file=/etc/vsftpd.chroot_list\n\
allow_writeable_chroot=YES\n\
local_umask=0002\n\
ssl_enable=YES\n\
rsa_cert_file=/etc/ssl/private/vsftpd.pem\n\
rsa_private_key_file=/etc/ssl/private/vsftpd.pem\n\
allow_anon_ssl=NO\n\
force_local_data_ssl=YES\n\
force_local_logins_ssl=YES\n\
ssl_tlsv1=YES\n\
ssl_sslv2=NO\n\
ssl_sslv3=NO\n\
require_ssl_reuse=NO\n\
ssl_ciphers=HIGH\n\
EOF'",
        "sudo touch /etc/vsftpd.chroot_list",
        "sudo bash -c 'echo ftpuser >> /etc/vsftpd.chroot_list'",
        "sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem -subj \"/C=IN/ST=Delhi/L=Delhi/O=my/OU=main/CN=myftp/emailAddress=ftpuser@gmail.com\"",
        "sudo systemctl restart --now vsftpd"
    ]

    for command in commands:
        run_command(command)






def connect_ftp(host, port=21, username="anonymous", password=""):
    try:
        ftp = FTP()
        ftp.connect(host=host, port=port)
        ftp.login(user=username, passwd=password)  # Anonymous login by default
        st.success(f"✅ Successfully connected to FTP server at {host} as anonymous!")
        
        # Display some server info
        st.info(f"Server response: {ftp.getwelcome()}")
        ftp.quit()
        return True
    except Exception as e:
        st.error(f"❌ Failed to connect to FTP server: {str(e)}")
        return False


def apply_default_configuration():
    default_config_steps = [
        ("Install VSFTPD", "sudo apt install vsftpd"),
        ("Enable VSFTPD", "sudo systemctl enable --now vsftpd"),
        ("Configure Firewall", """sudo ufw allow 20/tcp
sudo ufw allow 21/tcp
sudo ufw allow 990/tcp
sudo ufw allow 5000:10000/tcp"""),
        ("Create FTP User", "sudo adduser ftpuser"),
        ("Configure SSH", """sudo nano /etc/ssh/sshd_config
DenyUsers ftpuser
sudo systemctl restart sshd"""),
        ("Setup FTP Directory", """sudo mkdir /ftp
sudo chown adminuser /ftp"""),
        ("Configure VSFTPD", """anonymous_enable=NO
local_enable=YES
write_enable=YES
pasv_min_port=5000
pasv_max_port=10000
local_root=/ftp 
chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
allow_writeable_chroot=YES
local_umask=0002"""),
        ("Setup SSL Certificate", """sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem"""),
        ("Configure SSL Settings", """rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH""")
    ]
    
    # Get sudo password
    sudo_password = st.text_input("Enter sudo password to apply configuration:", type="password")
    
    if st.button("Apply Default Configuration"):
        if not sudo_password:
            st.error("Password is required to proceed.")
            return
        
        try:
            for step_name, config in default_config_steps:
                with st.status(f"Applying {step_name}..."):
                    if 'nano' in config:
                        st.code(config, language="bash")
                        st.info("This step requires manual editing. Please copy the configuration and apply it manually.")
                        continue
                    
                    command = f'echo {sudo_password} | sudo -S bash -c "{config}"'
                    process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                    st.success(f"✅ {step_name} completed successfully!")
                    
            st.success("🎉 Default configuration applied successfully!")
            
        except subprocess.CalledProcessError as e:
            st.error(f"Failed to apply configuration: {str(e)}")
            st.error(f"Error output: {e.stderr}")


def server_config_page():
    st.title("Server Configuration Panel")
    
    st.title("Server Configuration Panel")
    
    # Add Default Configuration Section
    st.header("Quick Setup")
    with st.expander("Default Server Configuration"):
        st.write("This will apply a secure default configuration for your FTP server.")
        st.info("""This will:
        1. Install and enable VSFTPD
        2. Configure firewall rules
        3. Create FTP user and directory
        4. Set up SSL/TLS encryption
        5. Apply secure default settings""")
        apply_default_configuration()

    if 'enable_ssh' not in st.session_state:
        st.session_state.enable_ssh = False
    
    # Shared Network Settings
    st.header("Network Settings")


    # SSH Enable/Disable Toggle
    st.header("SSH Configuration")
    st.session_state.enable_ssh = st.toggle("Enable SSH Server", st.session_state.enable_ssh)
    
    if st.session_state.enable_ssh:
        # [Previous SSH configuration code remains the same...]
        # SSH Authentication Settings
        st.subheader("Authentication Settings")
        permit_root_login = st.selectbox("Permit Root Login", ["yes", "no", "prohibit-password", "without-password"])
        password_authentication = st.checkbox("Allow Password Authentication", value=False)
        pubkey_authentication = st.checkbox("Enable Public Key Authentication", value=True)
        permit_empty_passwords = st.checkbox("Allow Empty Passwords", value=False)
        use_pam = st.checkbox("Enable PAM Authentication", value=False)
        
        # SSH Security Settings
        st.subheader("Security Settings")
        max_auth_tries = st.number_input("Max Authentication Attempts", min_value=1, max_value=10, value=6)
        max_sessions = st.number_input("Max Sessions", min_value=1, max_value=100, value=10)
        denied_users = st.text_area("Denied Users (comma-separated)", "ftpuser")
        
        # SSH Key Configuration
        st.subheader("🔑 Host Keys")
        host_keys = st.multiselect("Select Host Keys", [
            "/etc/ssh/ssh_host_rsa_key",
            "/etc/ssh/ssh_host_ecdsa_key",
            "/etc/ssh/ssh_host_ed25519_key"
        ])
        
        # SFTP Configuration
        st.subheader("SFTP Configuration")
        enable_sftp = st.checkbox("Enable SFTP", value=True)
        sftp_chroot_directory = st.text_input("Chroot Directory", "/var/www/")
        sftp_force_command = st.text_input("Force Command", "internal-sftp")
        
        # Generate SSH Configuration Preview
        st.subheader("SSH Configuration Preview")
        ssh_config_preview = f'''
PermitRootLogin {permit_root_login}
PasswordAuthentication {'yes' if password_authentication else 'no'}
PubkeyAuthentication {'yes' if pubkey_authentication else 'no'}
PermitEmptyPasswords {'yes' if permit_empty_passwords else 'no'}
UsePAM {'yes' if use_pam else 'no'}
MaxAuthTries {max_auth_tries}
DenyUsers {denied_users}
''' + "\n".join([f"HostKey {key}" for key in host_keys]) + f'''
Subsystem sftp {sftp_force_command if enable_sftp else '/usr/lib/ssh/sftp-server'}
Match User ftpuser
ChrootDirectory {sftp_chroot_directory}
ForceCommand {sftp_force_command}
'''
        st.code(ssh_config_preview, language="bash")
        
        if st.button("✅ Apply SSH Configuration"):
            apply_configuration(ssh_config_preview, "/etc/ssh/sshd_config")

    # FTP Server Configuration
    st.header("FTP Server Configuration")
    
    # FTP Basic Settings
    st.subheader("Access Control")
    anonymous_enable = st.checkbox("Allow Anonymous FTP Access", value=False)
    local_enable = st.checkbox("Allow Local Users to Log In", value=True)
    write_enable = st.checkbox("Enable FTP Write Commands", value=True)
    
    # FTP Security Settings
    st.subheader("Security Configuration")
    local_umask = st.select_slider("Local User Umask", 
                                    options=['022', '027', '077'],
                                    value='022')
    chroot_local_user = st.checkbox("Chroot Local Users (Jail to Home Directory)", value=True)
    allow_writeable_chroot = st.checkbox("Allow Writeable Chroot Directory", value=False)
    
    # FTP Connection Settings
    st.subheader("PASV Mode Configuration")
    pasv_enable = st.checkbox("Enable PASV Mode", value=True)
    if pasv_enable:
        col1, col2 = st.columns(2)
        with col1:
            pasv_min_port = st.number_input("PASV Minimum Port", min_value=1024, max_value=65535, value=40000)
        with col2:
            pasv_max_port = st.number_input("PASV Maximum Port", min_value=1024, max_value=65535, value=40100)
    
    # FTP Logging Settings
    st.subheader("Logging Configuration")
    xferlog_enable = st.checkbox("Enable Transfer Logging", value=True)
    if xferlog_enable:
        xferlog_std_format = st.checkbox("Use Standard Format for Logs", value=True)
        dual_log_enable = st.checkbox("Enable Dual Logging", value=True)
        xferlog_file = st.text_input("Log File Path", "/var/log/vsftpd.log")
    
    # FTP Timeout Settings
    st.subheader("Timeout Configuration")
    col1, col2 = st.columns(2)
    with col1:
        idle_session_timeout = st.number_input("Idle Session Timeout (seconds)", 
                                            min_value=60, max_value=3600, value=600)
    with col2:
        data_connection_timeout = st.number_input("Data Connection Timeout (seconds)", 
                                                min_value=30, max_value=1800, value=120)
    
    # FTP Display Settings
    st.subheader("Display Settings")
    ftpd_banner = st.text_area("FTP Banner Message", 
                                "Welcome to Secure FTP Server. Authorized access only.")
    dirmessage_enable = st.checkbox("Enable Directory Messages", value=True)
    
    # Generate FTP Configuration Preview
    st.subheader("FTP Configuration Preview")
    ftp_config_preview = f"""# vsftpd configuration file
# Basic Settings
anonymous_enable={'YES' if anonymous_enable else 'NO'}
local_enable={'YES' if local_enable else 'NO'}
write_enable={'YES' if write_enable else 'NO'}
local_umask={local_umask}

# Security Settings
chroot_local_user={'YES' if chroot_local_user else 'NO'}
allow_writeable_chroot={'YES' if allow_writeable_chroot else 'NO'}

# Connection Settings
listen=YES
connect_from_port_20=YES
pasv_enable={'YES' if pasv_enable else 'NO'}
""" + (f"""pasv_min_port={pasv_min_port}
pasv_max_port={pasv_max_port}
""" if pasv_enable else "") + f"""
# Logging Settings
xferlog_enable={'YES' if xferlog_enable else 'NO'}
""" + (f"""xferlog_std_format={'YES' if xferlog_std_format else 'NO'}
dual_log_enable={'YES' if dual_log_enable else 'NO'}
xferlog_file={xferlog_file}
""" if xferlog_enable else "") + f"""
# Timeout Settings
idle_session_timeout={idle_session_timeout}
data_connection_timeout={data_connection_timeout}

# Display Settings
ftpd_banner={ftpd_banner}
dirmessage_enable={'YES' if dirmessage_enable else 'NO'}

# PAM Service Name
pam_service_name=vsftpd
"""

    if not anonymous_enable:
        col1, col2 = st.columns(2)
        with col1:
            ftp_username = st.text_input("Username")
        with col2:
            ftp_password = st.text_input("Password", type="password")

    else:
        ftp_username = "anonymous"
        ftp_password = "anonymous@example.com"
    
    st.code(ftp_config_preview, language="bash")
    
    if st.button("✅ Apply FTP Configuration"):
        apply_configuration(ftp_config_preview, "/etc/vsftpd.conf")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if 'connect_host' not in st.session_state:
            st.session_state.connect_host = "0.0.0.0"  # Default value
        connect_host = st.text_input("FTP Server IP", value=st.session_state.connect_host)
    
    with col2:
        connect_port = st.number_input("Connection Port", value=21, min_value=1, max_value=65535)
    
    with col3:
        if st.button("🔄 Fetch Public IP", key="connect_fetch_ip"):
            fetched_ip = get_public_ip()
            if fetched_ip:
                st.session_state.connect_host = fetched_ip  # Update session state with the fetched IP
                st.rerun()  # Rerun the app to update the input field
    
    if st.button("🔌 Connect to FTP Server"):
        with st.spinner("Attempting to connect to FTP server..."):
            connect_ftp(st.session_state.connect_host, ftp_username, ftp_password, connect_port)
    
    # Server Control Panel at the bottom
    st.markdown("---")
    server_control_panel()







def main():
    st.set_page_config(page_title="🔐 Serveset_pager Configuration Panel", layout="wide")
    server_config_page()

if __name__ == "__main__":
    main()