import os
import hashlib
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

LOG_FILE = "sample_auth.log"
REPORT_FILE = "security_report.txt"

FAILED_LOGIN_LIMIT = 3


def create_sample_log():
    if os.path.exists(LOG_FILE):
        return

    sample_lines = [
        "2026-09-15 09:10:01 | LOGIN_SUCCESS | user=admin | ip=192.168.1.10",
        "2026-09-15 09:11:10 | LOGIN_FAILED | user=admin | ip=192.168.1.50",
        "2026-09-15 09:11:20 | LOGIN_FAILED | user=admin | ip=192.168.1.50",
        "2026-09-15 09:11:30 | LOGIN_FAILED | user=admin | ip=192.168.1.50",
        "2026-09-15 09:15:00 | LOGIN_SUCCESS | user=student | ip=192.168.1.20",
        "2026-09-15 09:20:12 | LOGIN_FAILED | user=test | ip=10.0.0.25",
        "2026-09-15 09:21:14 | LOGIN_FAILED | user=test | ip=10.0.0.25",
        "2026-09-15 09:22:20 | LOGIN_FAILED | user=test | ip=10.0.0.25",
        "2026-09-15 09:23:25 | LOGIN_FAILED | user=test | ip=10.0.0.25"
    ]

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        for line in sample_lines:
            file.write(line + "\n")


def hide_ip(ip_address):
    encoded_ip = ip_address.encode("utf-8")
    hashed_ip = hashlib.sha256(encoded_ip).hexdigest()
    return hashed_ip[:12]


def read_log_file():
    failed_ips = {}
    success_count = 0
    failed_count = 0

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line == "":
                continue

            if "LOGIN_SUCCESS" in line:
                success_count += 1

            elif "LOGIN_FAILED" in line:
                failed_count += 1

                parts = line.split("|")
                ip_part = parts[3].strip()
                ip_address = ip_part.replace("ip=", "")

                if ip_address not in failed_ips:
                    failed_ips[ip_address] = 0

                failed_ips[ip_address] += 1

    return failed_ips, success_count, failed_count


def get_risk_level(failed_attempts):
    if failed_attempts >= 5:
        return "CRITICAL", 60

    elif failed_attempts >= 3:
        return "HIGH", 40

    elif failed_attempts >= 1:
        return "MEDIUM", 20

    else:
        return "LOW", 0


def create_report(
    failed_ips,
    success_count,
    failed_count
):
    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(REPORT_FILE, "a", encoding="utf-8") as file:
        file.write("\n")
        file.write("=" * 50 + "\n")
        file.write("SENTINELMESH SECURITY REPORT\n")
        file.write("=" * 50 + "\n")
        file.write(f"Generated: {current_time}\n")
        file.write(f"Successful logins: {success_count}\n")
        file.write(f"Failed logins: {failed_count}\n")
        file.write("\nSuspicious IP addresses:\n")

        for ip_address, count in failed_ips.items():
            if count >= FAILED_LOGIN_LIMIT:
                risk_level, score = get_risk_level(count)
                private_ip = hide_ip(ip_address)

                file.write(
                    f"IP ID: {private_ip} | "
                    f"Attempts: {count} | "
                    f"Risk: {risk_level} | "
                    f"Score: {score}\n"
                )


def display_result(
    failed_ips,
    success_count,
    failed_count
):
    print("\n" + Style.BRIGHT)
    print("SENTINELMESH SECURITY RESULT")
    print("-" * 40)

    print(f"Successful logins: {success_count}")
    print(f"Failed logins: {failed_count}")

    print("\nSuspicious IP addresses:")

    found_suspicious_ip = False

    for ip_address, count in failed_ips.items():
        if count >= FAILED_LOGIN_LIMIT:
            found_suspicious_ip = True

            risk_level, score = get_risk_level(count)
            private_ip = hide_ip(ip_address)

            print(
                Fore.RED
                + f"ALERT: IP ID {private_ip}"
            )

            print(f"Failed attempts: {count}")
            print(f"Risk level: {risk_level}")
            print(f"Risk score: {score}")

    if found_suspicious_ip is False:
        print(Fore.GREEN + "No suspicious IP found.")


def main():
    print(Style.BRIGHT + "================================")
    print("       SENTINELMESH")
    print(" Security Log Analyzer")
    print("================================")

    print(
        "\nThis program analyzes your own sample "
        "authentication log."
    )

    create_sample_log()

    choice = input(
        "\nPress 1 to analyze the log: "
    ).strip()

    if choice != "1":
        print("Invalid choice. Program closed.")
        return

    failed_ips, success_count, failed_count = (
        read_log_file()
    )

    display_result(
        failed_ips,
        success_count,
        failed_count
    )

    create_report(
        failed_ips,
        success_count,
        failed_count
    )

    print(
        "\nReport created successfully:"
        f" {REPORT_FILE}"
    )


if __name__ == "__main__":
    main()