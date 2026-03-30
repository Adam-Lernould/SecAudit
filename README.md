# SecAudit: Linux Security Audit Script

## Description
SecAudit is a lightweight and automated Bash script designed to analyze the security configurations of essential Linux services. It quickly identifies common misconfigurations, high-risk vulnerabilities, and permissive access rights, then generates a clear and readable report.

Currently, SecAudit checks the following services if they are active on the system:
* **SSH:** Audits `/etc/ssh/sshd_config` for root login, empty passwords, password authentication, and session timeouts.
* **Apache2:** Audits `/etc/apache2/apache2.conf` for directory listing (`Options Indexes`), server signature footprinting, and Cross-Site Tracing (`TraceEnable`).
* **Cron:** Checks the presence of `cron.allow`, and verifies strict access rights (`rwx`) and root ownership for `/etc/crontab` and `/etc/cron.{hourly,daily,weekly,monthly}` directories.

## How to Use

**Note:** This script requires administrator privileges (`root`) to access and read the system configuration files and service statuses.

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Adam-Lernould/SecAudit.git](https://github.com/Adam-Lernould/SecAudit.git)
   cd SecAudit
   ```

2. **Make it executable if it's not already**
   ```bash
   chmod +x SecAudit.sh
   ```

3. **Run it !**
   ```bash
   sudo ./SecAudit.sh
   ```
