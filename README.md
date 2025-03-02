# System Hardening Script

![Bash](https://img.shields.io/badge/Language-Bash-green)
![License](https://img.shields.io/badge/License-MIT-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A comprehensive and automated system hardening script for Linux, designed to enhance security by applying best practices and configurations. Perfect for cybersecurity enthusiasts, students, and professionals.

---

## Table of Contents
- [About the Project](#about-the-project)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Usage](#usage)
- [Script Workflow](#script-workflow)
- [Contribution](#contribution)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## About the Project

This project is a **Linux System Hardening Script** that automates the process of securing a Linux system. It was developed as part of my journey as a cybersecurity student, driven by a passion for system security and automation. The script applies a series of security best practices, including:

- System updates and package management
- Kernel security parameter configuration
- SSH and firewall hardening
- Password policy enforcement
- Lynis security audits

Whether you're a beginner or an experienced professional, this script provides a solid foundation for securing Linux systems. Contributions and improvements are welcome!

---

## Features

- **Cross-Distribution Support**: Works with `apt`, `dnf`, `yum`, `pacman`, and `zypper` package managers.
- **Interactive Prompts**: Allows users to confirm or skip each hardening step.
- **Comprehensive Hardening**:
  - Disables unnecessary services
  - Applies secure kernel parameters
  - Hardens SSH and firewall configurations
  - Enforces strong password policies
- **Lynis Integration**: Runs a Lynis security audit before and after hardening to measure effectiveness.
- **Progress Tracking**: Displays a progress bar to track the completion of each step.
- **Logging**: Logs all actions to `/var/log/system_hardening.log` for review.

---

## Getting Started

### Prerequisites

- A Linux-based system (tested on Ubuntu, CentOS, and Arch Linux)
- Root or sudo privileges
- Internet access (for package installation and Lynis download)

### Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/system-hardening-script.git
   cd system-hardening-script
   ```

2. Make the script executable:
   ```bash
   chmod +x system_hardening.sh
   ```

3. Run the script as root:
   ```bash
   sudo ./system_hardening.sh
   ```

4. Follow the on-screen prompts to confirm or skip each hardening step.

5. Review the logs at `/var/log/system_hardening.log` for details on the changes made.

6. Reboot the system after the script completes for all changes to take effect.

---

## Script Workflow

1. **Introduction**: Displays a colorful introduction and waits for user confirmation to proceed.
2. **System Update**: Updates the system and removes obsolete packages.
3. **Enhanced Security**: Applies kernel security parameters and disables unnecessary services.
4. **File Permission Hardening**: Removes SUID/SGID bits and fixes permissions on critical files.
5. **SELinux Installation**: Installs and configures SELinux (if supported).
6. **SSH Hardening**: Configures secure SSH parameters and disables root login.
7. **Firewall Configuration**: Installs and configures UFW to allow only essential services.
8. **Password Policy Enforcement**: Enforces strong password requirements and aging rules.
9. **Lynis Audit**: Runs a Lynis security audit before and after hardening.

---

## Contribution

Contributions are welcome! If you have suggestions, improvements, or new features to add, feel free to open an issue or submit a pull request. Here’s how you can contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your message here"
   ```
4. Push to the branch:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a pull request and describe your changes.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- **Lynis**: A fantastic security auditing tool. Learn more at [https://cisofy.com/lynis/](https://cisofy.com/lynis/).
- **Linux Community**: For the wealth of knowledge and resources available online.
- **Open Source Contributors**: For inspiring me to contribute to the cybersecurity community.

---

**Happy Hardening!** 🛡️



