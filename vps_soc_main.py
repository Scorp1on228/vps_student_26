import tempfile
from pathlib import Path

import vps_soc_analyzer as analyzer
from vps_log_generator import generate_mock_nginx_logs, generate_mock_ssh_logs


def run_pipeline() -> None:
    print("=" * 60)
    print("ЗАПУСК КОНВЕЙЕРА (PIPELINE) МИНИ-SOC НА VPS")
    print("=" * 60)

    with tempfile.TemporaryDirectory(prefix="vps-soc-") as temporary_directory:
        workspace = Path(temporary_directory)
        ssh_log_path = workspace / "mock_auth.log"
        nginx_log_path = workspace / "mock_nginx_access.log"
        config_path = workspace / "vps_secure_config.conf"

        print("[1] Симуляция: создаем искусственные логи...")
        ssh_logs = generate_mock_ssh_logs(num_lines=100)
        nginx_logs = generate_mock_nginx_logs(num_lines=50)
        ssh_log_path.write_text("\n".join(ssh_logs) + "\n", encoding="utf-8")
        nginx_log_path.write_text("\n".join(nginx_logs) + "\n", encoding="utf-8")
        print(f"    - Строк SSH: {len(ssh_logs)}")
        print(f"    - Строк Nginx: {len(nginx_logs)}")

        print("-" * 60)
        print("[2] Анализ SSH логов:")
        ip_attempts = analyzer.group_by_ip(ssh_logs)
        print(f"    - Уникальных IP с неудачным входом: {len(ip_attempts)}")
        for ip_address, count in sorted(
            ip_attempts.items(), key=lambda item: item[1], reverse=True
        )[:3]:
            print(f"      * IP: {ip_address} - {count} неудачных попыток")
        brute_force_alerts = analyzer.detect_brute_force(ip_attempts)
        print(f"    - Брутфорс-атак (>= 5 попыток): {len(brute_force_alerts)}")
        for ip_address in brute_force_alerts:
            print(f"      [ALERT] IP {ip_address} превысил порог")

        print("-" * 60)
        print("[3] Анализ веб-логов (Nginx):")
        web_alerts = [
            log_line
            for log_line in nginx_logs
            if analyzer.detect_suspicious_paths(log_line)
        ]
        for log_line in web_alerts:
            parts = log_line.split('"')
            request = parts[1] if len(parts) > 1 else log_line
            ip_address = log_line.split()[0]
            print(f"      [ALERT] {ip_address} запросил опасный путь: '{request}'")
        print(f"    - Подозрительных веб-запросов: {len(web_alerts)}")

        print("-" * 60)
        print("[4] Оценка уровня угрозы VPS:")
        risk = analyzer.calculate_risk_score(len(brute_force_alerts), len(web_alerts))
        print(f"    - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")

        print("-" * 60)
        print("[5] Контроль целостности файлов:")
        config_path.write_text(
            "PermitRootLogin no\nPasswordAuthentication no\n",
            encoding="utf-8",
        )
        original_hash = analyzer.get_file_hash(str(config_path))
        print(f"    - SHA-256 до изменения: {original_hash}")
        with config_path.open("a", encoding="utf-8") as config_file:
            config_file.write("PermitRootLogin yes # Изменение конфигурации\n")
        modified_hash = analyzer.get_file_hash(str(config_path))
        print(f"    - SHA-256 после изменения: {modified_hash}")
        if original_hash != modified_hash:
            print("    - [!] Целостность конфигурации нарушена.")
        else:
            print("    - [OK] Файл конфигурации не изменен.")

        print("-" * 60)
        print("[6] Проверка доступности портов на localhost:")
        for port in (22, 80, 443, 8080):
            status = (
                "ОТКРЫТ"
                if analyzer.is_port_open("127.0.0.1", port)
                else "ЗАКРЫТ"
            )
            print(f"      * Порт {port}: {status}")

    print("КОНВЕЙЕР ЗАВЕРШИЛ РАБОТУ.")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()
