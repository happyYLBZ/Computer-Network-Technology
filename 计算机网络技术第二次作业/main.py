import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import csv
import sys
import binascii

# Windows混杂模式相关参数
SIO_RCVALL = 0x98000001 # Windows 特有的套接字（socket）控制码，用于设置网卡为混杂模式
RCVALL_ON = 1  #开启
RCVALL_OFF = 0 #关闭

# 协议编号
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

""" 辅助函数 """

#将4字节二进制 IPv4 地址转换为点分十进制字符串（如 b'\xC0\xA8\x01\x01' 转化为 '192.168.1.1'）
def inet_ntoa(raw):
    return socket.inet_ntoa(raw)

#解析 IPv4 协议头
def parse_ipv4_header(data):
    # IPv4 最小头部长度是 20 字节
    if len(data) < 20:
        return None
    # 按网络字节序（大端字节序）拆解前 20 字节：
    ver_ihl, tos, total_length, identification, flags_frag, ttl, proto, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', data[:20])
    # 版本号
    version = ver_ihl >> 4
    # 头部长度
    ihl = ver_ihl & 0x0F
    header_length = ihl * 4
    return {
        'version': version,                               # IP版本号
        'ihl': ihl,                                       # IP 头部长度字段
        'header_length': header_length,                   # IP 头部长度
        'tos': tos,                                       # 服务类型
        'total_length': total_length,                     # 整个 IP 包长度（头 + 数据）
        'id': identification,                             # 标识
        'flags_frag': flags_frag,                         # 标志 + 分片偏移
        'ttl': ttl,                                       # 生存时间
        'protocol': proto,                                # 上层协议类型
        'checksum': checksum,                             # IP头部的校验和
        'src': inet_ntoa(src),                            # 源 IP 地址
        'dst': inet_ntoa(dst),                            # 目的 IP 地址
        'payload': data[header_length:total_length]       # IP 数据部分
    }

# 解析 TCP 协议头
def parse_tcp_header(data):
    # TCP头部最小 20 字节
    if len(data) < 20:
        return None
    # 拆解前20字节
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    return {
        'src_port': src_port,      # 源端口号
        'dst_port': dst_port,      # 目标端口号
        'seq': seq,                # 序列号
        'ack': ack,                # 确认号
        'offset': offset,          # TCP 头部长度
        'flags': flags,            # 标志
        'window': window,          # 窗口大小
        'checksum': checksum,      # 校验和
        'urg_ptr': urg_ptr,        # 紧急指针
        'payload': data[offset:]   # TCP 携带的实际数据
    }

# 解析 UDP 协议头
def parse_udp_header(data):
    # UDP头部固定8字节
    if len(data) != 8:
        return None
    # 拆解UDP头部
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return {
        'src_port': src_port, # 源端口号
        'dst_port': dst_port, # 目标端口号
        'length': length,     # UDP 报文总长度
        'checksum': checksum, # 校验和
        'payload': data[8:]   # UDP真正的数据
    }

# 解析 ICMP 协议头
def parse_icmp_header(data):
    # ICMP头部固定4字节
    if len(data) < 4:
        return None
    # 拆解ICMP头部
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return {
        'type': icmp_type,    # ICMP类型
        'code': code,         # ICMP子类型
        'checksum': checksum, # 校验和
        'payload': data[4:]   # ICMP数据部分
    }

# 可视化数据包内容
def hexdump(data, length=16):
    result = []
    for i in range(0, len(data), length):
        s = data[i:i+length]
        hexa = ' '.join(['%02X' % b for b in s])
        text = ''.join([chr(b) if 32 <= b < 127 else '.' for b in s])
        result.append('%04X   %-48s   %s' % (i, hexa, text))
    return '\n'.join(result)

# 用于对抓取到的 IPv4 数据包进行统计分析、协议识别和流量表记录
class PacketAnalyzer:
    # 初始化
    def __init__(self):
        self.total = 0
        self.by_protocol = {'TCP':0,'UDP':0,'ICMP':0,'OTHER':0}
        self.high_level = {'HTTP':0,'DNS':0,'DHCP':0}
        self.flow_table = {}  # key: (src,dst,proto,srcport,dstport)
    # 数据包分析
    def analyze(self, ip):
        self.total += 1
        proto = ip['protocol']
        if proto == IP_PROTO_TCP:
            self.by_protocol['TCP'] += 1
            try:
                tcp = parse_tcp_header(ip['payload'])
                if tcp:
                    self._inspect_tcp(ip, tcp)
            except Exception:
                pass
        elif proto == IP_PROTO_UDP:
            self.by_protocol['UDP'] += 1
            try:
                udp = parse_udp_header(ip['payload'])
                if udp:
                    self._inspect_udp(ip, udp)
            except Exception:
                pass
        elif proto == IP_PROTO_ICMP:
            self.by_protocol['ICMP'] += 1
        else:
            self.by_protocol['OTHER'] += 1

        # 更新
        key = (ip['src'], ip['dst'], proto)
        self.flow_table.setdefault(key, 0)
        self.flow_table[key] += 1

    # 判断抓到的 TCP 包是否属于 HTTP 流量
    def _inspect_tcp(self, ip, tcp):
        payload = tcp['payload']
        if tcp['src_port'] == 80 or tcp['dst_port'] == 80:
            self.high_level['HTTP'] += 1
        else:
            if payload and (payload.startswith(b'GET ') or payload.startswith(b'POST ') or b'HTTP/' in payload[:16]):
                self.high_level['HTTP'] += 1

    # 检测抓到的 UDP 包是否属于 DNS 或 DHCP 流量
    def _inspect_udp(self, ip, udp):
        if udp['src_port'] == 53 or udp['dst_port'] == 53:
            self.high_level['DNS'] += 1
        if (udp['src_port'] in (67,68)) or (udp['dst_port'] in (67,68)):
            self.high_level['DHCP'] += 1
    # 文本报告
    def report_text(self):
        parts = []
        parts.append('Traffic Analysis Report - %s' % datetime.datetime.now().isoformat())
        parts.append('Total IPv4 packets: %d' % self.total)
        parts.append('By IP-level protocol:')
        for k,v in self.by_protocol.items():
            parts.append('  %s: %d' % (k, v))
        parts.append('Detected high-level protocols:')
        for k,v in self.high_level.items():
            parts.append('  %s: %d' % (k, v))
        parts.append('\nFlow table (sample):')
        for (src,dst,proto), cnt in list(self.flow_table.items())[:200]:
            parts.append('  %s -> %s  proto=%s  packets=%d' % (src, dst, proto, cnt))
        return '\n'.join(parts)

    # 导出表格
    def export_csv(self, filepath):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Report generated', datetime.datetime.now().isoformat()])
            writer.writerow([])
            writer.writerow(['Total IPv4 packets', self.total])
            writer.writerow([])
            writer.writerow(['Protocol','Count'])
            for k,v in self.by_protocol.items():
                writer.writerow([k,v])
            writer.writerow([])
            writer.writerow(['High-level protocol','Count'])
            for k,v in self.high_level.items():
                writer.writerow([k,v])
            writer.writerow([])
            writer.writerow(['Flow Src','Flow Dst','Proto','Packets'])
            for (src,dst,proto), cnt in self.flow_table.items():
                writer.writerow([src,dst,proto,cnt])


class RawSnifferGUI:
    # 初始化
    def __init__(self, root):
        self.root = root
        self.root.title('Windows IPv4 Raw Sniffer')
        self.running = False
        self.sock = None
        self.capture_thread = None
        self.analyzer = PacketAnalyzer()
        self.packet_raw = {}

        self._build_ui()
    # 构建图形用户界面
    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=8)
        frame.grid(row=0, column=0, sticky='nsew')

        # 顶部控件
        controls = ttk.Frame(frame)
        controls.grid(row=0, column=0, sticky='ew')

        # 本地IP输入框
        ttk.Label(controls, text='Local IP to bind:').grid(row=0, column=0, sticky='w')
        self.local_ip_var = tk.StringVar(value=self._guess_local_ip())
        self.local_ip_entry = ttk.Entry(controls, textvariable=self.local_ip_var, width=16)
        self.local_ip_entry.grid(row=0, column=1, sticky='w')

        # 抓包过滤器输入框
        ttk.Label(controls, text='Filter (single IP or pair ip1,ip2):').grid(row=0, column=2, sticky='w', padx=(10,0))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(controls, textvariable=self.filter_var, width=30)
        self.filter_entry.grid(row=0, column=3, sticky='w')

        # 开始抓包按钮
        self.start_btn = ttk.Button(controls, text='Start Capture', command=self.start_capture)
        self.start_btn.grid(row=0, column=4, padx=6)

        # 停止抓包按钮
        self.stop_btn = ttk.Button(controls, text='Stop Capture', command=self.stop_capture, state='disabled')
        self.stop_btn.grid(row=0, column=5)

        # 导出报告
        self.export_btn = ttk.Button(controls, text='Export Report', command=self.export_report)
        self.export_btn.grid(row=0, column=6, padx=(8,0))

        # 中间抓包列表
        columns = ('time','version','src','dst','proto','info')
        self.tree = ttk.Treeview(frame, columns=columns, show='headings', height=18)
        for c in columns:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=100, anchor='w')
        self.tree.grid(row=1, column=0, sticky='nsew', pady=(8,0))

        # 统计信息
        stats_frame = ttk.Frame(frame)
        stats_frame.grid(row=2, column=0, sticky='ew', pady=(8,0))
        self.stats_label = ttk.Label(stats_frame, text='Packets: 0 | TCP:0 UDP:0 ICMP:0 OTHER:0 | HTTP:0 DNS:0 DHCP:0')
        self.stats_label.grid(row=0, column=0, sticky='w')

        # 详细信息
        detail_frame = ttk.Frame(frame)
        detail_frame.grid(row=3, column=0, sticky='nsew', pady=(8,0))
        detail_label = ttk.Label(detail_frame, text='Selected packet hex / details')
        detail_label.grid(row=0, column=0, sticky='w')
        self.detail_text = tk.Text(detail_frame, height=12, wrap='none')
        self.detail_text.grid(row=1, column=0, sticky='nsew')

        # 绑定事件
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        # 设置布局伸缩比例
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(0, weight=1)

    # 自动获取本机 IP，用于绑定抓包
    def _guess_local_ip(self):
        try:
            host = socket.gethostname()
            ip = socket.gethostbyname(host)
            return ip
        except Exception:
            return '0.0.0.0'
    # 开始抓包
    def start_capture(self):
        if self.running:
            return
        ip = self.local_ip_var.get().strip()
        if not ip:
            messagebox.showerror('Error', 'Please enter a local IP to bind to.')
            return
        flt = self._parse_filter(self.filter_var.get().strip())
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sock.bind((ip, 0))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            try:
                self.sock.ioctl(SIO_RCVALL, RCVALL_ON)
            except Exception as e:
                messagebox.showwarning('Warning', f'Could not enable RCVALL: {e}\nYou may still capture some traffic but results may be limited.')

            self.running = True
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.capture_thread = threading.Thread(target=self._capture_loop, args=(flt,), daemon=True)
            self.capture_thread.start()
        except PermissionError:
            messagebox.showerror('Permission error', 'Administrator privileges are required to open a raw socket on Windows. Run the program as Administrator.')
        except Exception as e:
            messagebox.showerror('Socket error', f'Could not open raw socket: {e}')

    # 停止抓包
    def stop_capture(self):
        if not self.running:
            return
        self.running = False
        # 关闭混杂模式
        try:
            if self.sock:
                self.sock.ioctl(SIO_RCVALL, RCVALL_OFF)
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    # 解析过滤器
    def _parse_filter(self, txt):
        if not txt:
            return None
        parts = [p.strip() for p in txt.split(',') if p.strip()]
        if len(parts) == 1:
            return ('single', parts[0])
        elif len(parts) == 2:
            return ('pair', (parts[0], parts[1]))
        else:
            return None

    # 抓包线程
    def _capture_loop(self, flt):
        while self.running:
            try:
                raw, addr = self.sock.recvfrom(65535)
            except OSError:
                break
            try:
                ip = parse_ipv4_header(raw)
                if not ip:
                    continue
                if ip['version'] != 4:
                    continue
                if not self._filter_match(ip, flt):
                    continue
                proto = ip['protocol']
                if proto == IP_PROTO_TCP:
                    proto_name = 'TCP'
                elif proto == IP_PROTO_UDP:
                    proto_name = 'UDP'
                elif proto == IP_PROTO_ICMP:
                    proto_name = 'ICMP'
                else:
                    proto_name = str(proto)

                t = datetime.datetime.now().strftime('%H:%M:%S')
                self.root.after(0, self._insert_packet_row, t, ip['version'], ip['src'], ip['dst'], proto_name, raw)
                self.analyzer.analyze(ip)
                self.root.after(0, self._update_stats)
            except Exception as e:
                pass

    # 过滤器
    def _filter_match(self, ip, flt):
        if not flt:
            return True
        kind = flt[0]
        if kind == 'single':
            x = flt[1]
            return ip['src'] == x or ip['dst'] == x
        elif kind == 'pair':
            a,b = flt[1]
            return (ip['src'] == a and ip['dst'] == b) or (ip['src'] == b and ip['dst'] == a)
        return True

    # 插入抓包记录
    def _insert_packet_row(self, time_s, version, src, dst, proto, raw):
        info = ''
        try:
            ip = parse_ipv4_header(raw)
            if ip['protocol'] == IP_PROTO_TCP:
                tcp = parse_tcp_header(ip['payload'])
                if tcp:
                    info = f"{tcp['src_port']}->{tcp['dst_port']} len={len(tcp['payload'])}"
                    if tcp['payload']:
                        first = tcp['payload'].split(b'\r\n',1)[0]
                        if any(first.startswith(m) for m in (b'GET ', b'POST ', b'PUT ', b'HTTP/')):
                            try:
                                info += ' HTTP'
                            except Exception:
                                pass
            elif ip['protocol'] == IP_PROTO_UDP:
                udp = parse_udp_header(ip['payload'])
                if udp:
                    info = f"{udp['src_port']}->{udp['dst_port']} len={udp['length']}"
                    if udp['src_port'] in (53, ) or udp['dst_port'] in (53, ):
                        info += ' DNS'
                    if udp['src_port'] in (67,68) or udp['dst_port'] in (67,68):
                        info += ' DHCP'
        except Exception:
            pass

        iid = self.tree.insert('', 0, values=(time_s, version, src, dst, proto, info))
        self.packet_raw[iid] = raw

        if len(self.tree.get_children()) > 2000:
            children = self.tree.get_children()
            for c in children[2000:]:
                self.tree.delete(c)

    # 更新统计
    def _update_stats(self):
        s = self.analyzer
        text = f"Packets: {s.total} | TCP:{s.by_protocol['TCP']} UDP:{s.by_protocol['UDP']} ICMP:{s.by_protocol['ICMP']} OTHER:{s.by_protocol['OTHER']} | HTTP:{s.high_level['HTTP']} DNS:{s.high_level['DNS']} DHCP:{s.high_level['DHCP']}"
        self.stats_label.config(text=text)

    # 查看选中包
    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        raw = self.packet_raw.get(item)
        if not raw:
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, "No raw packet available")
            return
        try:
            ip = parse_ipv4_header(raw)
            out = []
            out.append(f"Time: {self.tree.set(item,'time')}")
            out.append(f"Version: {ip['version']} IHL: {ip['ihl']} HeaderLen: {ip['header_length']}")
            out.append(f"Src: {ip['src']} -> Dst: {ip['dst']} Protocol: {ip['protocol']} TTL: {ip['ttl']}")
            out.append('\nHex dump:')
            out.append(hexdump(raw))
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, '\n'.join(out))
        except Exception as e:
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, f'Could not show packet: {e}')

    # 导出报告
    def export_report(self):
        if self.analyzer.total == 0:
            messagebox.showinfo('No data', 'No packets captured yet. Nothing to export.')
            return
        f = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text file','*.txt'),('CSV','*.csv')])
        if not f:
            return
        try:
            if f.lower().endswith('.csv'):
                self.analyzer.export_csv(f)
            else:
                with open(f, 'w', encoding='utf-8') as fh:
                    fh.write(self.analyzer.report_text())
            messagebox.showinfo('Exported', f'Report saved to {f}')
        except Exception as e:
            messagebox.showerror('Export error', f'Could not save report: {e}')


if __name__ == '__main__':
    # 若不是Windows系统则结束
    if sys.platform != 'win32':
        print('This script is intended to run on Windows.')
        sys.exit(1)
    # 创建主窗口
    root = tk.Tk()
    # 初始化GUI
    app = RawSnifferGUI(root)
    # 定义“关闭窗口按钮”的行为
    root.protocol('WM_DELETE_WINDOW', lambda: (app.stop_capture(), root.destroy()))
    # 启动 GUI 主循环
    root.mainloop()
