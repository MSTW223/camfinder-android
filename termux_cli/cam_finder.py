#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CamFinder - أداة اكتشاف كاميرات المراقبة على الشبكة المحلية
لفنيي تركيب أنظمة المراقبة (Dahua / Hikvision وغيرها)

ما تفعله الأداة:
  - تمسح الشبكة المحلية (LAN) وتكتشف الأجهزة المتصلة (ping sweep)
  - تفحص البورتات الشائعة للكاميرات: 80 (ويب), 554 (RTSP), 8000 (Hikvision), 37777 (Dahua)
  - ترسل طلب ONVIF WS-Discovery (بروتوكول معياري) لتتعرف الكاميرا نفسها على نوعها وماركتها
  - تولّد روابط جاهزة: رابط صفحة الويب الخاصة بالكاميرا + رابط RTSP تقريبي حسب الماركة
  - تصدّر النتائج كملف CSV لتوثيق التركيب

ما لا تفعله الأداة (مهم):
  - لا تجرب أي اسم مستخدم/كلمة مرور (لا brute force ولا قاموس كلمات)
  - لا تحاول اختراق أو تجاوز أي حماية
  - تعمل فقط على الشبكة المحلية التي أنت متصل بها فعليًا (شبكة العميل أثناء التركيب)

يعمل على:
  - أي كمبيوتر فيه Python 3 (ويندوز/لينكس/ماك)
  - أندرويد عبر تطبيق Termux (مجاني - F-Droid أو GitHub)

طريقة التشغيل على أندرويد (Termux):
  1) ثبّت تطبيق Termux من F-Droid
  2) داخل Termux اكتب:
       pkg update && pkg install python -y
  3) انسخ هذا الملف إلى الهاتف (عبر Google Drive أو كيبل USB) ثم:
       python cam_finder.py
  4) تأكد إن هاتفك متصل بنفس شبكة الواي فاي الخاصة بالكاميرات

طريقة التشغيل على كمبيوتر:
       python3 cam_finder.py
"""

import socket
import struct
import subprocess
import sys
import platform
import ipaddress
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# إعدادات عامة
# ---------------------------------------------------------------------------

# البورتات التي نفحصها لكل جهاز، مع وصف كل بورت
CAMERA_PORTS = {
    80: "Web / HTTP",
    554: "RTSP (بث الفيديو)",
    8000: "Hikvision SDK",
    37777: "Dahua SDK/TCP",
    8080: "Web (بديل)",
    443: "HTTPS",
}

PING_TIMEOUT_MS = 500
PORT_TIMEOUT_S = 0.6
MAX_WORKERS = 64

ONVIF_MULTICAST_ADDR = "239.255.255.250"
ONVIF_MULTICAST_PORT = 3702
ONVIF_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{msg_id}</w:MessageID>
    <w:To e:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action e:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""


def clear_screen():
    pass  # نتجنب مسح الشاشة حتى تبقى الرسائل ظاهرة في Termux


def get_local_subnet():
    """
    يحاول تحديد الشبكة المحلية (مثال: 192.168.1.0/24) تلقائيًا
    بالاعتماد على عنوان IP الخاص بالجهاز نفسه.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # نفترض شبكة /24 (الأكثر شيوعًا في المنازل والمحلات)
        network = ipaddress.ip_network(local_ip + "/24", strict=False)
        return local_ip, network
    except Exception:
        return None, None


def ping_host(ip):
    """يرسل ping واحد للجهاز ويرجع True إذا رد."""
    system_name = platform.system().lower()
    if "windows" in system_name:
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), str(ip)]
    else:
        # لينكس / ماك / أندرويد (Termux)
        timeout_s = max(1, PING_TIMEOUT_MS // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), str(ip)]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_port(ip, port, timeout=PORT_TIMEOUT_S):
    """يفحص بورت واحد فقط (محاولة اتصال TCP عادية - بدون أي تخمين لكلمة مرور)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            return result == 0
    except Exception:
        return False


def discover_hosts(network):
    """
    يمسح كل عناوين الشبكة المحلية (ping sweep) ويرجع قائمة
    بالأجهزة التي ردت (أي أنها متصلة وفعّالة).
    """
    hosts = list(network.hosts())
    alive = []
    print(f"[*] جاري مسح {len(hosts)} عنوان على الشبكة {network} ...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        done = 0
        for future in as_completed(futures):
            ip = futures[future]
            done += 1
            if future.result():
                alive.append(ip)
            if done % 20 == 0 or done == len(hosts):
                print(f"\r[*] تم فحص {done}/{len(hosts)} ...", end="", flush=True)
    print()
    return alive


def scan_ports_for_host(ip):
    """يفحص كل بورتات الكاميرات المعروفة لجهاز واحد."""
    open_ports = []
    for port in CAMERA_PORTS:
        if scan_port(ip, port):
            open_ports.append(port)
    return ip, open_ports


def guess_brand(open_ports):
    """
    تخمين مبدئي للماركة بناءً على البورتات المفتوحة فقط
    (هذا تخمين تقريبي فقط للمساعدة؛ ONVIF يعطي نتيجة أدق).
    """
    if 37777 in open_ports:
        return "Dahua (محتمل)"
    if 8000 in open_ports:
        return "Hikvision (محتمل)"
    if 554 in open_ports and 80 in open_ports:
        return "كاميرا IP (ماركة غير محددة)"
    return "-"


def onvif_discovery(timeout=3):
    """
    يرسل طلب ONVIF WS-Discovery عبر الشبكة (multicast) ويستمع للردود.
    هذا بروتوكول معياري تدعمه كل كاميرات ONVIF (يشمل أغلب كاميرات Dahua و Hikvision)
    وهو ليس اختراقًا - الكاميرا نفسها تعلن عن وجودها وماركتها بشكل طوعي.
    """
    import uuid

    print("[*] جاري البحث عبر ONVIF (WS-Discovery) ...")
    found = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        ttl = struct.pack("b", 2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        probe = ONVIF_PROBE.format(msg_id=uuid.uuid4())
        sock.sendto(probe.encode("utf-8"), (ONVIF_MULTICAST_ADDR, ONVIF_MULTICAST_PORT))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                # نحاول استخراج رابط الجهاز (XAddrs) من الرد
                xaddr = ""
                if "<d:XAddrs>" in text:
                    xaddr = text.split("<d:XAddrs>")[1].split("</d:XAddrs>")[0].strip()
                found[ip] = xaddr
            except socket.timeout:
                break
        sock.close()
    except Exception as e:
        print(f"[!] تعذّر تنفيذ ONVIF discovery: {e}")
    return found


def build_links(ip, open_ports, brand):
    """يولّد روابط جاهزة تساعد في التنصيب (ويب + RTSP تقريبي)."""
    links = {}
    if 80 in open_ports:
        links["web"] = f"http://{ip}/"
    elif 8080 in open_ports:
        links["web"] = f"http://{ip}:8080/"
    elif 443 in open_ports:
        links["web"] = f"https://{ip}/"

    if 554 in open_ports:
        if "Dahua" in brand:
            links["rtsp"] = f"rtsp://{ip}:554/cam/realmonitor?channel=1&subtype=0"
        elif "Hikvision" in brand:
            links["rtsp"] = f"rtsp://{ip}:554/Streaming/Channels/101"
        else:
            links["rtsp"] = f"rtsp://{ip}:554/"
    return links


def main():
    print("=" * 60)
    print("   CamFinder - أداة اكتشاف كاميرات المراقبة على الشبكة المحلية")
    print("   (بحث فقط - بدون أي تخمين لكلمات مرور)")
    print("=" * 60)

    local_ip, network = get_local_subnet()
    if not network:
        print("[!] تعذّر تحديد الشبكة تلقائيًا.")
        manual = input("أدخل نطاق الشبكة يدويًا (مثال 192.168.1.0/24): ").strip()
        try:
            network = ipaddress.ip_network(manual, strict=False)
        except Exception:
            print("[!] نطاق غير صالح. إنهاء البرنامج.")
            sys.exit(1)
    else:
        print(f"[*] عنوان جهازك: {local_ip}")
        print(f"[*] نطاق الشبكة المكتشف: {network}")
        change = input("اضغط Enter للمتابعة، أو اكتب نطاقًا آخر: ").strip()
        if change:
            try:
                network = ipaddress.ip_network(change, strict=False)
            except Exception:
                print("[!] نطاق غير صالح، سنستخدم النطاق المكتشف تلقائيًا.")

    # 1) مسح ONVIF أولاً (سريع ويعطي معلومات دقيقة عن الماركة)
    onvif_results = onvif_discovery()

    # 2) مسح الشبكة بالكامل (ping sweep)
    alive_hosts = discover_hosts(network)
    print(f"[*] عدد الأجهزة المتصلة المكتشفة: {len(alive_hosts)}")

    if not alive_hosts and not onvif_results:
        print("[!] لم يتم العثور على أي أجهزة. تأكد من الاتصال بنفس شبكة الواي فاي.")
        return

    # دمج أجهزة ONVIF مع قائمة الأجهزة الحية (حتى لو لم ترد على ping)
    all_ips = set(alive_hosts) | {ipaddress.ip_address(ip) for ip in onvif_results}

    # 3) فحص البورتات لكل جهاز
    print("[*] جاري فحص بورتات الكاميرات لكل جهاز مكتشف ...")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_ports_for_host, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip, open_ports = future.result()
            if open_ports or str(ip) in onvif_results:
                results.append((ip, open_ports))

    if not results:
        print("[!] لم يتم العثور على أي جهاز يفتح بورتات كاميرات معروفة.")
        return

    # 4) تجهيز وعرض النتائج
    print("\n" + "=" * 90)
    print(f"{'IP':<16} {'البورتات المفتوحة':<30} {'الماركة المحتملة':<22} {'ONVIF':<6}")
    print("=" * 90)

    report_rows = []
    for ip, open_ports in sorted(results, key=lambda x: x[0]):
        ip_str = str(ip)
        ports_str = ", ".join(f"{p}({CAMERA_PORTS.get(p,'')})" for p in open_ports) or "-"
        has_onvif = "نعم" if ip_str in onvif_results else "لا"
        brand = guess_brand(open_ports)
        if has_onvif == "نعم":
            # إن أعطانا ONVIF رابط جهاز، فهذا دليل أقوى إنها كاميرا فعلية
            brand = brand if brand != "-" else "كاميرا ONVIF (ماركة غير محددة)"

        print(f"{ip_str:<16} {ports_str:<30} {brand:<22} {has_onvif:<6}")

        links = build_links(ip_str, open_ports, brand)
        report_rows.append({
            "ip": ip_str,
            "open_ports": ports_str,
            "brand_guess": brand,
            "onvif": has_onvif,
            "onvif_xaddr": onvif_results.get(ip_str, ""),
            "web_link": links.get("web", ""),
            "rtsp_link_guess": links.get("rtsp", ""),
        })

    print("=" * 90)

    # 5) روابط جاهزة للتنصيب
    print("\n[*] روابط جاهزة للمساعدة في التنصيب:")
    for row in report_rows:
        print(f"  - {row['ip']}:")
        if row["web_link"]:
            print(f"      صفحة الويب : {row['web_link']}")
        if row["rtsp_link_guess"]:
            print(f"      رابط RTSP (تقريبي، تحقق من رقم القناة) : {row['rtsp_link_guess']}")
        if row["onvif_xaddr"]:
            print(f"      عنوان ONVIF : {row['onvif_xaddr']}")

    # 6) تصدير CSV لتوثيق التركيب
    save = input("\nهل تريد حفظ النتائج كملف CSV لتوثيق التركيب؟ (y/n): ").strip().lower()
    if save == "y":
        filename = f"camfinder_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=list(report_rows[0].keys()))
            writer.writeheader()
            writer.writerows(report_rows)
        print(f"[*] تم حفظ التقرير في: {filename}")

    print("\n[*] تذكير: الأداة لا تختبر أي كلمة مرور. لتسجيل الدخول استخدم بيانات العميل")
    print("    أو اتصل بموزّع الكاميرا لاسترجاع كلمة المرور الافتراضية حسب الموديل.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] تم إيقاف البرنامج بواسطة المستخدم.")
