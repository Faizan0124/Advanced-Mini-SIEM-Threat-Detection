import datetime

start_time = datetime.datetime(2023, 10, 25, 10, 0, 0)
with open("logs.txt", "a") as f:
    # Adding a massive brute-force attack block
    for i in range(500):
        timestamp = (start_time + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] LOGIN_FAIL user=ceo_account ip=133.33.33.77 reason=brute_force_attack\n")
        
    # Adding a few Safe logs afterwards
    for i in range(50):
        timestamp = (start_time + datetime.timedelta(seconds=500 + i)).strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] AUTH SUCCESS user=sysadmin ip=10.0.1.15 session_id=XYZ123\n")
        
    # Adding a specific file deletion event
    timestamp = (start_time + datetime.timedelta(seconds=550)).strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"[{timestamp}] FILE_DELETE path=/var/log/audit.log user=root status=success\n")

print("Appended new concentrated attack logs to logs.txt")
