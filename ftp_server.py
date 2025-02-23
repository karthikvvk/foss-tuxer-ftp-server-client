import time
from ftplib import FTP
import streamlit as st
import os
import subprocess
import requests
from pathlib import Path

# -----------------------------------------------------------------------------
# Helper functions for UI elements with info popups
# -----------------------------------------------------------------------------
def header_with_info(text, info):
    col1, col2 = st.columns([0.9, 0.1])
    with col1:
        st.header(text)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)

def subheader_with_info(text, info):
    col1, col2 = st.columns([0.9, 0.1])
    with col1:
        st.subheader(text)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)




def text_input_with_info(label, default="", info="", type="default"):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        if type == "password":
            value = st.text_input(label, default, type="password")
        else:
            value = st.text_input(label, default)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

def number_input_with_info(label, default, info="", **kwargs):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        value = st.number_input(label, value=default, **kwargs)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

def checkbox_with_info(label, default, info=""):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        value = st.checkbox(label, value=default)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

def selectbox_with_info(label, options, default=None, info=""):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        index = options.index(default) if default in options else 0
        value = st.selectbox(label, options, index=index)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

def text_area_with_info(label, default="", info=""):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        value = st.text_area(label, default)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

def select_slider_with_info(label, options, default, info=""):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        value = st.select_slider(label, options=options, value=default)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

def toggle_with_info(label, default, info=""):
    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        value = st.toggle(label, default)
    with col2:
        with st.expander("ℹ️"):
            st.write(info)
    return value

# -----------------------------------------------------------------------------
# Other functions (unchanged core logic)
# -----------------------------------------------------------------------------
def ensure_directory_exists(filepath):
    directory = os.path.dirname(filepath)
    if not os.path.exists(directory):
        os.makedirs(directory)

def apply_configuration(config_content, file_path):
    # Administrator prompt with info icon
    subheader_with_info("Administrator Permission Required", 
                         "Enter your sudo password to apply configuration changes to system files.")
    sudo_password = text_input_with_info("Enter your sudo password:", "", 
                                           "This password is required to run commands with sudo.", type="password")
    if st.button("Apply Configuration"):
        if not sudo_password:
            st.error("❌ Password is required to proceed.")
            return
        try:
            command = f'echo {sudo_password} | sudo -S tee -a {file_path}'
            subprocess.run(command, input=config_content, text=True, shell=True, check=True)
            st.success(f"✅ Configuration applied successfully to {file_path}!")
        except subprocess.CalledProcessError as e:
            st.error(f"❌ Failed to apply configuration: {str(e)}")
            st.info("Make sure the password is correct and you have sudo privileges.")

def get_public_ip():
    try:
        response = requests.get('https://ifconfig.me')
        if response.status_code == 200:
            return response.text.strip()
        else:
            raise Exception(f"Failed to fetch IP: HTTP {response.status_code}")
    except Exception as e:
        st.error(f"Failed to fetch public IP: {str(e)}")
        return None

def server_control_panel():
    header_with_info("Server Control Panel", 
                     "Control panel to manage server status: start, stop, or restart the server.")
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

def connect_ftp(host, port=21, username="anonymous", password=""):
    try:
        ftp = FTP()
        ftp.connect(host=host, port=port)
        ftp.login(user=username, passwd=password)
        st.success(f"✅ Successfully connected to FTP server at {host} as anonymous!")
        st.info(f"Server response: {ftp.getwelcome()}")
        ftp.quit()
        return True
    except Exception as e:
        st.error(f"❌ Failed to connect to FTP server: {str(e)}")
        return False

# -----------------------------------------------------------------------------
# Main server configuration page with info popups for each heading and input
# -----------------------------------------------------------------------------
def server_config_page():
    st.title("Server Configuration Panel")
    
    if 'enable_ssh' not in st.session_state:
        st.session_state.enable_ssh = False

    header_with_info("Network Settings", 
                     "Configure network parameters and connectivity settings for the server.")
    
    header_with_info("SSH Configuration", 
                     "Configure SSH service including authentication, security, and key management.")
    st.session_state.enable_ssh = toggle_with_info("Enable SSH Server", st.session_state.enable_ssh, 
                                                   "Toggle to enable or disable the SSH service.")
    
    if st.session_state.enable_ssh:
        subheader_with_info("Authentication Settings", 
                            "Settings for user authentication such as root login and password policies.")
        permit_root_login = selectbox_with_info("Permit Root Login", 
                                                ["yes", "no", "prohibit-password", "without-password"],
                                                default="yes",
                                                info="Allow or restrict root login for SSH.")
        password_authentication = checkbox_with_info("Allow Password Authentication", False,
                                                     "Enable or disable password-based authentication.")
        pubkey_authentication = checkbox_with_info("Enable Public Key Authentication", True,
                                                   "Enable public key based authentication for SSH.")
        permit_empty_passwords = checkbox_with_info("Allow Empty Passwords", False,
                                                    "Allow users with empty passwords to login (not recommended).")
        use_pam = checkbox_with_info("Enable PAM Authentication", False,
                                     "Enable Pluggable Authentication Modules for SSH.")
        
        subheader_with_info("Security Settings", 
                            "Settings to enforce security measures like maximum authentication attempts and session limits.")
        max_auth_tries = number_input_with_info("Max Authentication Attempts", 6,
                                                "Maximum number of authentication attempts allowed.",
                                                min_value=1, max_value=10)
        max_sessions = number_input_with_info("Max Sessions", 10,
                                              "Maximum number of simultaneous sessions allowed.",
                                              min_value=1, max_value=100)
        denied_users = text_area_with_info("Denied Users (comma-separated)", "ftpuser",
                                           "List users who are denied SSH access.")
        
        subheader_with_info("🔑 Host Keys", 
                            "Select the SSH host keys used for server identification and encryption.")
        host_keys = st.multiselect("Select Host Keys", [
            "/etc/ssh/ssh_host_rsa_key",
            "/etc/ssh/ssh_host_ecdsa_key",
            "/etc/ssh/ssh_host_ed25519_key"
        ])
        
        subheader_with_info("SFTP Configuration", 
                            "Configure SFTP settings for secure file transfers over SSH.")
        enable_sftp = checkbox_with_info("Enable SFTP", True,
                                         "Toggle to enable or disable SFTP functionality.")
        sftp_chroot_directory = text_input_with_info("Chroot Directory", "/var/www/",
                                                     "Directory to restrict SFTP users to.")
        sftp_force_command = text_input_with_info("Force Command", "internal-sftp",
                                                  "Command to force SFTP users to use (typically 'internal-sftp').")
        
        subheader_with_info("SSH Configuration Preview", 
                            "Preview the generated SSH configuration based on the selected settings.")
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
    
    header_with_info("FTP Server Configuration", 
                     "Configure the FTP server settings including access control, security, and connection options.")
    
    subheader_with_info("Access Control", 
                        "Settings to control FTP access for anonymous and local users.")
    anonymous_enable = checkbox_with_info("Allow Anonymous FTP Access", False,
                                          "Toggle to allow or disallow anonymous FTP access.")
    local_enable = checkbox_with_info("Allow Local Users to Log In", True,
                                      "Toggle to allow or disallow local user logins via FTP.")
    write_enable = checkbox_with_info("Enable FTP Write Commands", True,
                                      "Toggle to allow or disallow write commands in FTP.")
    
    subheader_with_info("Security Configuration", 
                        "Security settings for FTP, including chroot options and permissions.")
    local_umask = select_slider_with_info("Local User Umask", 
                                          options=['022', '027', '077'],
                                          default='022',
                                          info="File permission mask for local users.")
    chroot_local_user = checkbox_with_info("Chroot Local Users (Jail to Home Directory)", True,
                                           "Restrict local users to their home directory.")
    allow_writeable_chroot = checkbox_with_info("Allow Writeable Chroot Directory", False,
                                                "Allow chroot directories to be writeable (less secure).")
    
    subheader_with_info("PASV Mode Configuration", 
                        "Configure FTP passive mode settings for data connections.")
    pasv_enable = checkbox_with_info("Enable PASV Mode", True,
                                     "Toggle to enable or disable passive mode in FTP.")
    if pasv_enable:
        col1, col2 = st.columns(2)
        with col1:
            pasv_min_port = number_input_with_info("PASV Minimum Port", 40000,
                                                   "Minimum port number for passive mode data connections.")
        with col2:
            pasv_max_port = number_input_with_info("PASV Maximum Port", 40100,
                                                   "Maximum port number for passive mode data connections.")
    
    subheader_with_info("Logging Configuration", 
                        "Settings to enable and configure FTP logging.")
    xferlog_enable = checkbox_with_info("Enable Transfer Logging", True,
                                        "Toggle to enable logging of file transfers.")
    if xferlog_enable:
        xferlog_std_format = checkbox_with_info("Use Standard Format for Logs", True,
                                                "Toggle to use standard log format.")
        dual_log_enable = checkbox_with_info("Enable Dual Logging", True,
                                             "Toggle to enable dual logging of transfers.")
        xferlog_file = text_input_with_info("Log File Path", "/var/log/vsftpd.log",
                                            "Path to the FTP log file.")
    
    subheader_with_info("Timeout Configuration", 
                        "Configure idle session and data connection timeouts for FTP.")
    col1, col2 = st.columns(2)
    with col1:
        idle_session_timeout = number_input_with_info("Idle Session Timeout (seconds)", 600,
                                                      "Time in seconds before an idle session is disconnected.",
                                                      min_value=60, max_value=3600)
    with col2:
        data_connection_timeout = number_input_with_info("Data Connection Timeout (seconds)", 120,
                                                         "Time in seconds before a data connection times out.",
                                                         min_value=30, max_value=1800)
    
    subheader_with_info("Display Settings", 
                        "Settings for FTP server messages and directory display configurations.")
    ftpd_banner = text_area_with_info("FTP Banner Message", 
                                      "Welcome to Secure FTP Server. Authorized access only.",
                                      "Message displayed to users when they connect to the FTP server.")
    dirmessage_enable = checkbox_with_info("Enable Directory Messages", True,
                                           "Toggle to enable custom directory messages.")
    
    subheader_with_info("FTP Configuration Preview", 
                        "Preview the generated FTP configuration based on the current settings.")





    ftp_config_preview = f"""# vsftpd configuration file - Main configuration for Very Secure FTP Daemon

# Basic Settings
anonymous_enable={'YES' if anonymous_enable else 'NO'}        # Allow/disable anonymous FTP access (recommended: NO for security)
local_enable={'YES' if local_enable else 'NO'}            # Enable access for local system users with accounts
write_enable={'YES' if write_enable else 'NO'}            # Allow upload and file modification commands
local_umask={local_umask}            # File permission mask for uploaded files (022: group/others read-only)

# Security Settings
chroot_local_user={'YES' if chroot_local_user else 'NO'}       # Restrict users to their home directories (jail)
allow_writeable_chroot={'YES' if allow_writeable_chroot else 'NO'}   # Allow users to write to their chroot directory (security risk)

# Connection Settings
listen=YES                  # Enable standalone mode (recommended over inetd)
connect_from_port_20=YES    # Use port 20 for active mode data transfers
pasv_enable={'YES' if pasv_enable else 'NO'}             # Enable passive mode transfers (recommended for most clients)
"""
    # Add passive port range if enabled
    if pasv_enable:
        ftp_config_preview += f"""pasv_min_port={pasv_min_port}         # Lower bound of passive mode port range
pasv_max_port={pasv_max_port}         # Upper bound of passive mode port range
"""

    # Add logging configuration
    ftp_config_preview += f"""
# Logging Settings
xferlog_enable={'YES' if xferlog_enable else 'NO'}          # Enable logging of file transfers
"""
    if xferlog_enable:
        ftp_config_preview += f"""xferlog_std_format={'YES' if xferlog_std_format else 'NO'}      # Use standard wu-ftpd log format
dual_log_enable={'YES' if dual_log_enable else 'NO'}         # Enable logging in both formats
xferlog_file={xferlog_file}  # Path to store transfer logs
"""

    # Add remaining settings
    ftp_config_preview += f"""
# Timeout Settings
idle_session_timeout={idle_session_timeout}    # Time in seconds before disconnecting inactive users
data_connection_timeout={data_connection_timeout} # Time in seconds before closing idle data connections

# Display Settings
ftpd_banner={ftpd_banner}  # Welcome message shown to users upon connection
dirmessage_enable={'YES' if dirmessage_enable else 'NO'}       # Enable .message files in directories (shows directory info)

# PAM Service Name
pam_service_name=vsftpd     # PAM service name for user authentication
"""
    




    st.code(ftp_config_preview, language="bash")
    
    if not anonymous_enable:
        col1, col2 = st.columns(2)
        with col1:
            ftp_username = text_input_with_info("Username", "", "Enter FTP username")
        with col2:
            ftp_password = text_input_with_info("Password", "", "Enter FTP password", type="password")
    else:
        ftp_username = "anonymous"
        ftp_password = "anonymous@example.com"
    
    if st.button("✅ Apply FTP Configuration"):
        apply_configuration(ftp_config_preview, "/etc/vsftpd.conf")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if 'connect_host' not in st.session_state:
            st.session_state.connect_host = "0.0.0.0"
        connect_host = text_input_with_info("FTP Server IP", st.session_state.connect_host,
                                            "The IP address of the FTP server to connect to.")
    with col2:
        connect_port = number_input_with_info("Connection Port", 21,
                                               "The port number for the FTP connection.",
                                               min_value=1, max_value=65535)
    with col3:
        if st.button("🔄 Fetch Public IP", key="connect_fetch_ip"):
            fetched_ip = get_public_ip()
            if fetched_ip:
                st.session_state.connect_host = fetched_ip
                st.rerun()
    if st.button("🔌 Connect to FTP Server"):
        with st.spinner("Attempting to connect to FTP server..."):
            connect_ftp(st.session_state.connect_host, connect_port, ftp_username, ftp_password)
    
    st.markdown("---")
    server_control_panel()

def main():
    st.set_page_config(page_title="🔐 Server Configuration Panel", layout="wide")
    server_config_page()

if __name__ == "__main__":
    main()
