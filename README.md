Ái chà, tôi nhìn lại rồi — phần đánh số ở mục **"2. các bước cài đặt"** bị tụt mất số và mục **Cấu hình `.env**` bị đẩy ra thành một phần độc lập lớn, làm quy trình cài đặt bị đứt quãng và thiếu mất bước chạy chương trình.

Dưới đây là **bản `README.md` All-In-One chuẩn chỉnh đã gộp liền mạch toàn bộ quy trình cài đặt từ A-Z** (từ `git clone` $\rightarrow$ cài thư viện $\rightarrow$ tạo `.env` $\rightarrow$ chạy `main.py` nằm gọn trong 1 danh sách duy nhất không bị ngắt đoạn):

```markdown
<div align="center">

# 🔍 PCAP Artifact Extractor

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Focus-Digital%20Forensics-red.svg?style=for-the-badge&logo=spyder&logoColor=white)]()
[![VirusTotal](https://img.shields.io/badge/API-VirusTotal-blueviolet?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

**Công cụ tự động hóa phân tích file vết mạng (PCAP), trích xuất tệp tin/artifacts và đối soát mã độc qua VirusTotal API.**

---

</div>

## 📖 Bảng nội dung
- [✨ Tính năng chính](#-tính-năng-chính)
- [🚀 Hướng dẫn cài đặt & Sử dụng (A-Z)](#-hướng-dẫn-cài-đặt--sử-dụng-a-z)
- [📊 Kết quả mẫu (Sample Output)](#-kết-quả-mẫu-sample-output)
- [📁 Cấu trúc thư mục dự án](#-cấu-trúc-thư-mục-dự-án)
- [🛠️ Git Workflow Cheat Sheet](#️-git-workflow-cheat-sheet)
- [⚠️ Disclaimer](#️-disclaimer)

---

## ✨ Tính năng chính

- 📦 **Trích xuất Artifacts chuyên sâu:** Tự động phát hiện, phân tích và trích xuất tệp tin/dữ liệu truyền tải qua các giao thức mạng trong file `.pcap` / `.pcapng`.
- 🛡️ **Đối soát VirusTotal API:** Tự động tính toán băm (MD5/SHA256) của các artifact trích xuất được và truy vấn CSDL VirusTotal để phát hiện mối đe dọa.
- ⚡ **Thiết kế Modular:** Cấu trúc code tách biệt rõ ràng giữa core logic xử lý (`core/`) và luồng thực thi chính (`main.py`), dễ mở rộng parser mới.
- 🔐 **Bảo mật biến môi trường:** Quản lý chìa khóa API an toàn thông qua `.env`, chống lộ chìa khóa bảo mật khi đẩy lên GitHub.

---

## 🚀 Hướng dẫn cài đặt & Sử dụng (A-Z)

Yêu cầu hệ thống: **Python >= 3.10**, **pip** và **git**.

Thực hiện lần lượt 4 bước sau để chạy dự án:

### Bước 1: Clone Repository về máy
```bash
git clone [https://github.com/Chickennoexit/pcap-artifact-extractor.git](https://github.com/Chickennoexit/pcap-artifact-extractor.git)
cd pcap-artifact-extractor

```

### Bước 2: Cài đặt các thư viện phụ thuộc

```bash
pip install -r requirements.txt

```

### Bước 3: Cấu hình VirusTotal API Key (`.env`)

Tạo file `.env` từ file mẫu `.env.example` và điền API Key của bạn *(đăng ký miễn phí tại [VirusTotal API Portal](https://www.virustotal.com/gui/my-apikey))*:

```bash
# Tạo file .env từ template
cp .env.example .env

```

Nội dung trong file `.env`:

```env
# VirusTotal API Configuration
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here

# Thư mục lưu trữ kết quả trích xuất
OUTPUT_DIR=extracted_files

```

> ⚠️ **LƯU Ý BẢO MẬT:** File `.env` chứa key thật đã được liệt kê trong `.gitignore`. Tuyệt đối **KHÔNG** push file `.env` chứa key thật lên GitHub!

### Bước 4: Chạy chương trình

```bash
python main.py

```

---

## 📊 Kết quả mẫu (Sample Output)

```text
[+] Loading PCAP file...
[+] Extracted 3 artifacts from network stream:
    ├── [HTTP] payload_01.exe (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
    ├── [FTP] document.docx   (SHA256: 410654e6378e918809090333d838e1547820f12d2dd5f532... )
    └── [DNS] exfiltrated.txt 

[+] VirusTotal Scan Results:
    ⚠️  payload_01.exe -> MALICIOUS (48/72 vendors flagged)
    ✅ document.docx   -> CLEAN
    ℹ️  exfiltrated.txt -> UNKNOWN (File not found in VT database)

```

---

## 📁 Cấu trúc thư mục dự án

```text
pcap-artifact-extractor/
├── 📁 core/                # Thư mục chứa các module xử lý chính (Parsers, Extractor, VT Client,...)
├── 📄 .env.example         # File mẫu cấu hình biến môi trường
├── 📄 .gitignore            # Khai báo loại trừ các file rác / file môi trường local
├── 📄 main.py              # File thực thi chính của dự án (Entry point)
├── 📄 README.md            # Tài liệu hướng dẫn sử dụng dự án
└── 📄 requirements.txt     # Danh sách các thư viện Python phụ thuộc

```

---

## ⚠️ Disclaimer

Dự án **PCAP Artifact Extractor** được xây dựng phục vụ cho mục đích học tập, nghiên cứu bảo mật và hỗ trợ phân tích sự cố số (Digital Forensics & Incident Response - DFIR). Tác giả không chịu bất kỳ trách nhiệm nào đối với các hành vi sử dụng công cụ sai mục đích hoặc vi phạm pháp luật
