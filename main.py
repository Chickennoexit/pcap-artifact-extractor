import os
import sys
import hashlib
import asyncio
import magic

# ==============================================================================
# FIX COMPATIBILITY DÀNH RIÊNG CHO PYTHON 3.14 + PYSHARK
# (Patch các hàm asyncio đã bị gỡ bỏ trong Python 3.14)
# ==============================================================================
class DummyChildWatcher:
    def attach_loop(self, loop):
        pass

if not hasattr(asyncio, "get_child_watcher"):
    asyncio.get_child_watcher = lambda: DummyChildWatcher()
if not hasattr(asyncio, "set_child_watcher"):
    asyncio.set_child_watcher = lambda watcher: None
if not hasattr(asyncio, "SafeChildWatcher"):
    asyncio.SafeChildWatcher = object
# ==============================================================================

import pyshark
from rich.console import Console
from rich.table import Table
from core.vt_checker import check_virustotal_hash

console = Console()

def calculate_sha256(data_bytes):
    """Tính mã SHA-256 của byte array"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data_bytes)
    return sha256_hash.hexdigest()

def process_pcap(pcap_path, output_dir="./extracted_files"):
    """Trích xuất HTTP Artifacts từ PCAP và phân tích Threat Intel"""
    
    # Khởi tạo event loop an toàn cho Python 3.14 + pyshark
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    console.print(f"\n[bold blue][*] Đang phân tích file PCAP:[/] {pcap_path}")

    # Chỉ lọc các gói tin HTTP chứa Payload dữ liệu file
    display_filter = "http.file_data"
    cap = pyshark.FileCapture(pcap_path, display_filter=display_filter)

    # Dựng bảng hiển thị kết quả
    table = Table(title="PCAP MALWARE ARTIFACTS REPORT", title_style="bold magenta")
    table.add_column("ID", style="cyan", justify="center")
    table.add_column("Filename", style="yellow")
    table.add_column("Magic Bytes (MIME)", style="green")
    table.add_column("SHA-256 Hash", style="bold white")
    table.add_column("VirusTotal Status", justify="center")

    file_count = 0

    # Lặp qua từng gói tin khớp với filter
    for packet in cap:
        try:
            if hasattr(packet.http, 'file_data'):
                # 1. Chuyển Hex Payload từ pyshark thành raw bytes
                raw_hex = packet.http.file_data.replace(':', '')
                payload_bytes = bytes.fromhex(raw_hex)

                if not payload_bytes:
                    continue

                file_count += 1

                # 2. Nhận diện định dạng file thực sự bằng Magic Bytes
                mime_type = magic.from_buffer(payload_bytes)

                # 3. Tính mã SHA-256 của payload
                sha256_hash = calculate_sha256(payload_bytes)

                # 4. Trích xuất tên file gốc từ HTTP Header (nếu có)
                filename = f"artifact_{file_count}"
                if hasattr(packet.http, 'response_for_uri'):
                    uri_name = packet.http.response_for_uri.split('/')[-1]
                    if uri_name:
                        filename = uri_name

                # 5. Lưu file trích xuất vào thư mục output_dir
                save_path = os.path.join(output_dir, f"{file_count}_{filename}")
                with open(save_path, "wb") as f:
                    f.write(payload_bytes)

                # 6. Gọi VirusTotal API tra cứu Hash
                vt_result, color = check_virustotal_hash(sha256_hash)
                
                # Format màu sắc cảnh báo rủi ro
                if color == "RED":
                    vt_fmt = f"[bold red]{vt_result}[/]"
                elif color == "GREEN":
                    vt_fmt = f"[bold green]{vt_result}[/]"
                elif color == "YELLOW":
                    vt_fmt = f"[yellow]{vt_result}[/]"
                else:
                    vt_fmt = f"[dim]{vt_result}[/]"

                # Thêm dòng dữ liệu vào bảng
                table.add_row(
                    str(file_count),
                    filename,
                    mime_type,
                    f"{sha256_hash[:16]}...",  # Cắt gọn hash hiển thị
                    vt_fmt
                )

        except Exception:
            # Bỏ qua nếu gói tin bị hỏng (corrupted packet)
            continue

    cap.close()

    # Hiển thị kết quả ra Terminal
    if file_count > 0:
        console.print(table)
        console.print(f"[bold green][✓] Hoàn thành![/] Đã trích xuất {file_count} artifact(s) vào thư mục: [yellow]{output_dir}[/]\n")
    else:
        console.print("[bold red][!] Không tìm thấy HTTP Payload file nào trong file PCAP này.[/]\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_pcap = sys.argv[1]
    else:
        console.print("[bold red][Error] Thiếu đường dẫn file PCAP![/]")
        console.print("Cú pháp: [yellow]python main.py <path_to_pcap>[/]")
        sys.exit(1)

    if os.path.exists(target_pcap):
        process_pcap(target_pcap)
    else:
        console.print(f"[bold red][Error] File '{target_pcap}' không tồn tại![/]")
