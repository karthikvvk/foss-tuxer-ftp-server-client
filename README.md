# VSFTPD Quick Launch GUI

## Overview
This application simplifies the use of **VSFTPD (Very Secure FTP Daemon)** by providing an intuitive **Graphical User Interface (GUI)**. It eliminates the need for complex **command-line interfaces (CLI)**, making FTP server setup quick and hassle-free.

## Key Features

### **Ease of Use for Complex Software**
- Provides a **GUI-based** approach to configure and launch VSFTPD.
- Each parameter has an **information icon (ℹ️)** to explain its purpose.

### **Quick Launch Interface**
- One-click setup for **VSFTPD** with predefined configurations.
- Instantly hosts an FTP server based on user inputs such as:
  - **Remote availability** (Local Only or Remote Access)
  - **SSH/TLS/SSL connection** options
  - **User type and rights** management

### **Predefined Parameters**
- No manual configuration is needed.
- **Default settings** ensure a hassle-free setup experience.

### **Local Hosting**
- Instantly launch an FTP server on your **home machine** with a single click.

## Usage Guide

### 1. **VSFTPD Quick Setup**
- Click the **Quick Launch** button.
- The `quicklaunch()` function executes a step-by-step **automated setup**.

### 2. **Server Configuration Panel**
- Customize network settings, SSH configurations, FTP permissions, and more.
- Information icons (ℹ️) provide detailed descriptions for each setting.

### 3. **Server Control Panel**
- **Start**, **Stop**, or **Restart** the FTP server with a single click.
- Real-time status updates for server monitoring.

## Demo
Check out the demo here: [Demo Link](https://drive.google.com/drive/folders/1cb3L_gAJyFmIXC55Xk67S5OIIL5PqzOa?usp=sharing)

## Getting Started
1. **Install Dependencies** (Make sure Python & Streamlit are installed)
   ```sh
   pip install streamlit
   ```
2. **Run the Application**
   ```sh
   streamlit run app.py
   ```

## Technologies Used
- **Streamlit** (For GUI)
- **VSFTPD** (For FTP server)
- **Python** (For automation)

## Contributing
Contributions are welcome! Feel free to submit issues and pull requests.
