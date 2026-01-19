import socket
import ssl
import threading
import re
from bs4 import BeautifulSoup
import ctypes
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from email import message_from_bytes

class POP3ClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("POP3 邮件接收客户端")
        master.geometry("1000x1000")

        self.sock = None

        # ---------- 样式 ----------
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=6, font=('Arial', 11))
        style.configure("TLabel", font=('Arial', 11))
        style.configure("Header.TLabel", font=('Arial', 13, 'bold'))

        # ---------- 输入区 ----------
        frame_top = ttk.Frame(master, padding=10)
        frame_top.pack(fill='x')

        ttk.Label(frame_top, text="POP3 服务器:", style="Header.TLabel").grid(row=0, column=0, sticky='e')
        ttk.Label(frame_top, text="账号:", style="Header.TLabel").grid(row=1, column=0, sticky='e')
        ttk.Label(frame_top, text="密码:", style="Header.TLabel").grid(row=2, column=0, sticky='e')
        ttk.Label(frame_top, text="端口:", style="Header.TLabel").grid(row=3, column=0, sticky='e')

        self.server_entry = ttk.Entry(frame_top, width=35)
        self.user_entry = ttk.Entry(frame_top, width=35)
        self.pass_entry = ttk.Entry(frame_top, width=35, show="*")
        self.port_entry = ttk.Entry(frame_top, width=10)

        self.server_entry.grid(row=0, column=1, pady=3)
        self.user_entry.grid(row=1, column=1, pady=3)
        self.pass_entry.grid(row=2, column=1, pady=3)
        self.port_entry.grid(row=3, column=1, pady=3)
        self.port_entry.insert(0, "110")

        # ---------- 按钮 ----------
        frame_btn = ttk.Frame(master, padding=5)
        frame_btn.pack(fill='x')

        ttk.Button(frame_btn, text="连接", command=self.thread_connect).pack(side='left', padx=3)
        ttk.Button(frame_btn, text="登录", command=self.thread_login).pack(side='left', padx=3)
        ttk.Button(frame_btn, text="获取列表", command=self.thread_get_list).pack(side='left', padx=3)
        ttk.Button(frame_btn, text="下载邮件", command=self.thread_download_mail).pack(side='left', padx=3)
        ttk.Button(frame_btn, text="退出 QUIT", command=self.thread_quit).pack(side='left', padx=3)

        # ---------- 主体 ----------
        frame_main = ttk.Frame(master)
        frame_main.pack(fill='both', expand=True)

        self.mail_list = tk.Listbox(frame_main, width=40)
        self.mail_list.pack(side='left', fill='y')
        self.mail_list.bind("<Double-Button-1>", self.preview_mail)

        self.preview = scrolledtext.ScrolledText(frame_main, font=('Consolas', 11))
        self.preview.pack(side='right', fill='both', expand=True)

        ttk.Label(master, text="交互过程：", style="Header.TLabel").pack(anchor='w')
        self.output = scrolledtext.ScrolledText(master, height=10, font=('Consolas', 10))
        self.output.pack(fill='x', padx=10, pady=5)

    # ---------- 公共 ----------
    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def send_cmd(self, cmd):
        """发送命令，不直接接收响应"""
        self.sock.send((cmd + "\r\n").encode())
        self.log("C: " + cmd)

    def recv_line(self):
        """接收单行响应"""
        data = b""
        while b"\r\n" not in data:
            data += self.sock.recv(1)
        line = data.decode(errors="ignore").strip()
        self.log("S: " + line)
        return line

    def recv_multiline(self):
        """接收多行响应直到单独一行是 '.'"""
        data = ""
        while True:
            part = self.sock.recv(4096).decode(errors="ignore")
            data += part
            if "\r\n.\r\n" in data:
                break
        for line in data.splitlines():
            self.log("S: " + line)
        return data

    # ---------- 线程 ----------
    def thread_connect(self):
        threading.Thread(target=self.connect, daemon=True).start()

    def thread_login(self):
        threading.Thread(target=self.login, daemon=True).start()

    def thread_get_list(self):
        threading.Thread(target=self.get_list, daemon=True).start()

    def thread_download_mail(self):
        self.master.after(0, self.download_mail_prompt)

    def download_mail_prompt(self):
        msg_id = simpledialog.askinteger("下载邮件", "输入邮件编号：", parent=self.master)
        if msg_id is None:
            return
        threading.Thread(target=self.download_mail, args=(msg_id,), daemon=True).start()

    def thread_quit(self):
        threading.Thread(target=self.quit_pop3, daemon=True).start()

    # ---------- POP3 ----------
    def connect(self):
        server = self.server_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("端口错误", "请输入有效端口号")
            return
        if port not in (110, 995):
            messagebox.showerror("端口错误", "端口只能是 110 或 995")
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if port == 995:
                self.log("使用 SSL 连接...")
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.sock = context.wrap_socket(raw_sock, server_hostname=server)
            else:
                self.sock = raw_sock
                self.log("使用普通 TCP 连接...")
            self.sock.connect((server, port))
            banner = self.recv_line()
        except Exception as e:
            messagebox.showerror("连接错误", str(e))

    def login(self):
        try:
            self.send_cmd("USER " + self.user_entry.get())
            resp1 = self.recv_line()
            self.send_cmd("PASS " + self.pass_entry.get())
            resp2 = self.recv_line()

            # 登录成功后调用 STAT 获取邮箱状态
            if resp1.startswith("+OK") and resp2.startswith("+OK"):
                self.get_stat()
            else:
                self.log("登录失败，请检查账号或密码")
        except:
            messagebox.showerror("登录失败", "账号或密码错误")

    def get_stat(self):
        """获取邮箱状态：总邮件数和总大小"""
        try:
            self.send_cmd("STAT")
            resp = self.recv_line()
            if resp.startswith("+OK"):
                parts = resp.split()
                if len(parts) >= 3:
                    num_messages = parts[1]
                    total_size = int(parts[2])
                    if total_size > 1024 * 1024:
                        size_str = f"{total_size / 1024 / 1024:.2f} MB"
                    elif total_size > 1024:
                        size_str = f"{total_size / 1024:.1f} KB"
                    else:
                        size_str = f"{total_size} B"
                    self.log(f"邮箱状态：共 {num_messages} 封邮件，总大小 {size_str}")
                else:
                    self.log("STAT 响应格式异常")
            else:
                self.log("STAT 命令失败")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def get_list(self):
        try:
            self.send_cmd("LIST")
            resp = self.recv_line()
            if not resp.startswith("+OK"):
                self.log("获取列表失败")
                return

            data = self.recv_multiline()
            mails = []
            for line in data.splitlines():
                line = line.strip()
                if line == "" or line == ".":
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                num, size = parts
                size_int = int(size)
                if size_int > 1024 * 1024:
                    size_str = f"{size_int / 1024 / 1024:.2f} MB"
                elif size_int > 1024:
                    size_str = f"{size_int / 1024:.1f} KB"
                else:
                    size_str = f"{size_int} B"
                mails.append(f"{num}     {size_str}")

            self.master.after(0, lambda: self.update_mail_list(mails))
            self.log(f"邮件列表获取完成，共 {len(mails)} 封邮件")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def update_mail_list(self, mails):
        self.mail_list.delete(0, tk.END)
        for line in mails:
            self.mail_list.insert(tk.END, line)

    def download_mail(self, msg_id):
        try:
            self.send_cmd(f"RETR {msg_id}")
            resp = self.recv_line()
            if not resp.startswith("+OK"):
                self.log("获取邮件失败")
                return
            data = self.recv_multiline()
            path = f"mail_{msg_id}.eml"
            with open(path, "wb") as f:
                f.write(data.encode())
            self.log(f"邮件已保存为：{path}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def preview_mail(self, event):
        index = self.mail_list.curselection()
        if not index:
            return

        msg_no = self.mail_list.get(index).split()[0]

        # 发送 RETR 指令
        self.send_cmd(f"RETR {msg_no}")
        resp = self.recv_line()
        if not resp.startswith("+OK"):
            self.log("获取邮件失败")
            return

        # 获取完整邮件（EML 原文）
        data = self.recv_multiline()

        try:
            msg = message_from_bytes(data.encode() if isinstance(data, str) else data)
            body = ""

            if msg.is_multipart():
                # 优先提取 text/plain
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disp = str(part.get("Content-Disposition") or "")
                    charset = part.get_content_charset() or "utf-8"

                    if content_type == "text/plain" and "attachment" not in disp:
                        text = part.get_payload(decode=True).decode(charset, errors="ignore")
                        # 美化 text/plain：合并多空行，去掉多空格
                        text = re.sub(r'[ \t]+', ' ', text)
                        text = re.sub(r'\n\s*\n', '\n\n', text)
                        body += text

                # 如果 text/plain 为空，则尝试 text/html
                if not body:
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        disp = str(part.get("Content-Disposition") or "")
                        charset = part.get_content_charset() or "utf-8"

                        if content_type == "text/html" and "attachment" not in disp:
                            html = part.get_payload(decode=True).decode(charset, errors="ignore")
                            # HTML → 文本
                            soup = BeautifulSoup(html, "html.parser")
                            text = soup.get_text()
                            # 美化格式：去掉多空行和多空格
                            text = "\n".join([line.strip() for line in text.splitlines() if line.strip()])
                            text = re.sub(r'[ \t]+', ' ', text)
                            body = text
                            break
            else:
                charset = msg.get_content_charset() or "utf-8"
                payload = msg.get_payload(decode=True)
                if payload:
                    if msg.get_content_type() == "text/plain":
                        text = payload.decode(charset, errors="ignore")
                        text = re.sub(r'[ \t]+', ' ', text)
                        text = re.sub(r'\n\s*\n', '\n\n', text)
                        body = text
                    elif msg.get_content_type() == "text/html":
                        html = payload.decode(charset, errors="ignore")
                        soup = BeautifulSoup(html, "html.parser")
                        text = soup.get_text()
                        text = "\n".join([line.strip() for line in text.splitlines() if line.strip()])
                        text = re.sub(r'[ \t]+', ' ', text)
                        body = text

            if body.strip() == "":
                body = data

        except Exception as e:
            body = f"邮件解析失败：{e}\n\n原始内容：\n{data}"

        # 显示到预览窗口
        self.preview.delete("1.0", tk.END)
        self.preview.insert(tk.END, body)

    def quit_pop3(self):
        if self.sock:
            self.send_cmd("QUIT")
            self.recv_line()
            self.sock.close()
            self.sock = None
            self.log("连接已关闭")


if __name__ == "__main__":
    root = tk.Tk()
    POP3ClientGUI(root)
    root.mainloop()
