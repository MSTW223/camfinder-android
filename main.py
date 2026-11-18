# -*- coding: utf-8 -*-
"""
CamFinder - تطبيق أندرويد لاكتشاف كاميرات المراقبة على الشبكة المحلية
(Dahua / Hikvision / أي كاميرا IP تدعم ONVIF)

المبدأ:
  - اكتشاف فقط عبر فحص بورتات TCP عادي (connect scan) + ONVIF WS-Discovery
  - لا يوجد أي تخمين أو تجربة لكلمات مرور (لا brute force إطلاقًا)
  - يعمل على الشبكة المحلية التي يتصل بها الجهاز فعليًا فقط

ملاحظة تقنية: لا نستخدم ICMP ping لأن أندرويد يمنع raw sockets بدون صلاحية root،
لذلك نعتمد بالكامل على فحص اتصال TCP المباشر (connect_ex) وهو يعمل بدون أي صلاحيات خاصة.
"""

import socket
import struct
import threading
import uuid
import csv
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from kivy.app import App
from kivy.clock import mainthread
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.properties import StringProperty

try:
    from android.permissions import request_permissions, Permission  # noqa
    ANDROID = True
except Exception:
    ANDROID = False


CAMERA_PORTS = {
    80: "Web/HTTP",
    554: "RTSP",
    8000: "Hikvision",
    37777: "Dahua",
    8080: "Web-Alt",
    443: "HTTPS",
}

PORT_TIMEOUT_S = 0.5
MAX_WORKERS = 48

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


def get_local_ip_and_prefix():
    """يرجع (ip_محلي, أول_3_أجزاء_من_الشبكة) مثل ('192.168.1.5', '192.168.1')."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        prefix = ".".join(ip.split(".")[:3])
        return ip, prefix
    except Exception:
        return None, None


def scan_port(ip, port, timeout=PORT_TIMEOUT_S):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


def scan_host_ports(ip):
    open_ports = []
    for port in CAMERA_PORTS:
        if scan_port(ip, port):
            open_ports.append(port)
    return ip, open_ports


def guess_brand(open_ports, has_onvif):
    if 37777 in open_ports:
        return "Dahua (محتمل)"
    if 8000 in open_ports:
        return "Hikvision (محتمل)"
    if has_onvif:
        return "كاميرا ONVIF"
    if 554 in open_ports and 80 in open_ports:
        return "كاميرا IP"
    return "-"


def build_links(ip, open_ports, brand):
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


def onvif_discovery(timeout=3):
    """يرسل طلب ONVIF WS-Discovery (multicast UDP) ويستمع للردود الطوعية من الكاميرات."""
    found = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2))
        probe = ONVIF_PROBE.format(msg_id=uuid.uuid4())
        sock.sendto(probe.encode("utf-8"), (ONVIF_MULTICAST_ADDR, ONVIF_MULTICAST_PORT))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(65535)
                text = data.decode("utf-8", errors="ignore")
                xaddr = ""
                if "<d:XAddrs>" in text:
                    xaddr = text.split("<d:XAddrs>")[1].split("</d:XAddrs>")[0].strip()
                found[addr[0]] = xaddr
            except socket.timeout:
                break
        sock.close()
    except Exception:
        pass
    return found


class ResultRow(BoxLayout):
    """صف واحد في جدول النتائج."""

    def __init__(self, data, **kwargs):
        super().__init__(orientation="vertical", size_hint_y=None, height=120,
                          padding=8, spacing=2, **kwargs)
        with self.canvas.before:
            pass
        self.add_widget(Label(
            text=f"[b]{data['ip']}[/b]   ({data['brand']})",
            markup=True, size_hint_y=None, height=28,
            halign="right", valign="middle"))
        self.add_widget(Label(
            text=f"البورتات: {data['ports']}   ONVIF: {data['onvif']}",
            size_hint_y=None, height=24, font_size=13))
        if data.get("web"):
            self.add_widget(Label(text=f"ويب: {data['web']}", size_hint_y=None,
                                   height=22, font_size=12, color=(0.4, 0.8, 1, 1)))
        if data.get("rtsp"):
            self.add_widget(Label(text=f"RTSP: {data['rtsp']}", size_hint_y=None,
                                   height=22, font_size=12, color=(0.6, 1, 0.6, 1)))


class CamFinderRoot(BoxLayout):
    status_text = StringProperty("اضغط (بدء البحث) للبحث عن الكاميرات على الشبكة")

    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", padding=12, spacing=10, **kwargs)
        self.results_data = []

        self.status_label = Label(text=self.status_text, size_hint_y=None, height=40)
        self.add_widget(self.status_label)

        btn_row = BoxLayout(size_hint_y=None, height=50, spacing=10)
        self.scan_btn = Button(text="بدء البحث", on_release=self.start_scan)
        self.export_btn = Button(text="تصدير CSV", on_release=self.export_csv,
                                  disabled=True)
        btn_row.add_widget(self.scan_btn)
        btn_row.add_widget(self.export_btn)
        self.add_widget(btn_row)

        self.results_grid = GridLayout(cols=1, size_hint_y=None, spacing=6)
        self.results_grid.bind(minimum_height=self.results_grid.setter("height"))
        scroll = ScrollView()
        scroll.add_widget(self.results_grid)
        self.add_widget(scroll)

    def set_status(self, text):
        self.status_text = text
        self.status_label.text = text

    def start_scan(self, *_):
        self.scan_btn.disabled = True
        self.export_btn.disabled = True
        self.results_grid.clear_widgets()
        self.results_data = []
        self.set_status("جاري البحث عن الشبكة المحلية ...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        local_ip, prefix = get_local_ip_and_prefix()
        if not prefix:
            self._update_status("تعذّر تحديد الشبكة. تأكد من الاتصال بالواي فاي.")
            self._scan_done()
            return

        self._update_status(f"عنوانك: {local_ip} — جاري ONVIF discovery ...")
        onvif_results = onvif_discovery(timeout=3)

        self._update_status("جاري فحص بورتات الكاميرات على الشبكة (1-254) ...")
        candidates = [f"{prefix}.{i}" for i in range(1, 255)]
        found = []
        done = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(scan_host_ports, ip): ip for ip in candidates}
            for future in as_completed(futures):
                done += 1
                ip, open_ports = future.result()
                if open_ports or ip in onvif_results:
                    found.append((ip, open_ports))
                if done % 40 == 0:
                    self._update_status(f"تم فحص {done}/254 ...")

        if not found:
            self._update_status("لم يتم العثور على أي كاميرا. تأكد من نفس شبكة الواي فاي.")
            self._scan_done()
            return

        rows = []
        for ip, open_ports in sorted(found):
            has_onvif = ip in onvif_results
            brand = guess_brand(open_ports, has_onvif)
            links = build_links(ip, open_ports, brand)
            ports_str = ", ".join(f"{p}({CAMERA_PORTS.get(p,'')})" for p in open_ports) or "-"
            rows.append({
                "ip": ip,
                "ports": ports_str,
                "brand": brand,
                "onvif": "نعم" if has_onvif else "لا",
                "web": links.get("web", ""),
                "rtsp": links.get("rtsp", ""),
            })

        self._update_status(f"تم العثور على {len(rows)} جهاز محتمل.")
        self._populate_results(rows)
        self._scan_done()

    @mainthread
    def _update_status(self, text):
        self.set_status(text)

    @mainthread
    def _populate_results(self, rows):
        self.results_data = rows
        for row in rows:
            self.results_grid.add_widget(ResultRow(row))
        self.export_btn.disabled = False

    @mainthread
    def _scan_done(self):
        self.scan_btn.disabled = False

    def export_csv(self, *_):
        if not self.results_data:
            return
        try:
            if ANDROID:
                from android.storage import primary_external_storage_path
                base_dir = os.path.join(primary_external_storage_path(), "Download")
            else:
                base_dir = os.getcwd()
            os.makedirs(base_dir, exist_ok=True)
            filename = os.path.join(base_dir, f"camfinder_report_{int(time.time())}.csv")
            with open(filename, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=list(self.results_data[0].keys()))
                writer.writeheader()
                writer.writerows(self.results_data)
            self._show_popup("تم الحفظ", f"تم حفظ التقرير في:\n{filename}")
        except Exception as e:
            self._show_popup("خطأ", f"تعذّر حفظ الملف:\n{e}")

    def _show_popup(self, title, message):
        content = BoxLayout(orientation="vertical", padding=10, spacing=10)
        content.add_widget(Label(text=message))
        close_btn = Button(text="إغلاق", size_hint_y=None, height=44)
        content.add_widget(close_btn)
        popup = Popup(title=title, content=content, size_hint=(0.85, 0.4))
        close_btn.bind(on_release=popup.dismiss)
        popup.open()


class CamFinderApp(App):
    def build(self):
        self.title = "CamFinder"
        if ANDROID:
            try:
                request_permissions([
                    Permission.INTERNET,
                    Permission.ACCESS_NETWORK_STATE,
                    Permission.ACCESS_WIFI_STATE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                    Permission.READ_EXTERNAL_STORAGE,
                ])
            except Exception:
                pass
        return CamFinderRoot()


if __name__ == "__main__":
    CamFinderApp().run()
