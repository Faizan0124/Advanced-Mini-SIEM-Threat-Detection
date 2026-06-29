import random
import datetime

def generate_logs(num_lines=200000):
    safe_logs = [
        "INFO [kernel] System boot sequence initiated. Kernel version 5.15.0-89-generic.",
        "INFO [systemd] Started Network Manager.",
        "INFO [sshd] Server listening on 0.0.0.0 port 22.",
        "AUTH SUCCESS user=sysadmin ip=10.0.1.15 session_id=A123F",
        "DB_CONNECTION SUCCESS db=sales_db user=app_service",
        "CRON [root] CMD ( /usr/local/bin/backup.sh )",
        "WEB_ACCESS GET /index.html status=200 ip=192.168.1.100",
        "WEB_ACCESS GET /assets/style.css status=200 ip=192.168.1.100",
        "WEB_ACCESS GET /assets/logo.png status=200 ip=192.168.1.100",
        "AUTH SUCCESS user=j.doe ip=10.0.1.22 session_id=B456G",
        "CRON [root] CMD ( /opt/scripts/healthcheck.py )",
        "INFO [firewall] Dropped invalid packet from 192.168.1.45",
        "WEB_ACCESS POST /api/v1/data status=201 ip=10.0.1.15",
        "AUTH SUCCESS user=m.smith ip=10.0.1.34 session_id=C789H",
        "WEB_ACCESS GET /dashboard status=200 ip=10.0.1.22",
        "WEB_ACCESS GET /api/v1/metrics status=200 ip=10.0.1.22",
        "INFO [syslog] Log rotation completed successfully.",
        "AUTH SUCCESS user=svc_account ip=10.0.2.50 session_id=D012I",
        "CRON [root] CMD ( /usr/local/bin/sync_metrics.sh )",
        "WEB_ACCESS GET /login status=200 ip=203.0.113.5",
        "AUTH SUCCESS user=dev_team ip=203.0.113.5 session_id=E345J",
        "DB_CONNECTION SUCCESS db=analytics_db user=dev_team",
        "INFO [systemd] Started Daily Cleanup of Temporary Directories.",
        "WEB_ACCESS GET /api/v1/status status=200 ip=10.0.1.15"
    ]
    
    threat_logs = [
        "LOGIN_FAIL user=admin ip=45.33.22.11 reason=bad_password",
        "PORT_SCAN detected src=185.15.22.1 target_ports=22,80,443,3389,8080,8443",
        "PRIV_ESC sudo command execution successful user=www-data target=root command=\"bash -i\"",
        "FILE_DELETE path=/var/log/auth.log user=root status=success"
    ]
    
    start_time = datetime.datetime(2023, 10, 25, 8, 0, 0)
    
    with open("logs.txt", "w") as f:
        for i in range(num_lines):
            # 99.5% safe logs, 0.5% threats
            if random.random() > 0.005:
                log_msg = random.choice(safe_logs)
            else:
                log_msg = random.choice(threat_logs)
                
            timestamp = (start_time + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {log_msg}\n")

if __name__ == "__main__":
    generate_logs(200000)
    print("Generated 200,000 lines of logs in logs.txt")
