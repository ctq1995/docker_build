# -*- coding: utf-8 -*-
import base64
import os
import configparser
import paramiko
import threading
from tkinter import filedialog, messagebox
import tkinter as tk
import ttkbootstrap as ttk
from PIL.ImageTk import PhotoImage
from ttkbootstrap.constants import *
import time
import queue
import concurrent.futures
import asyncio
import random

# 新增的必要引用
import sys
import platform
import shutil
from pathlib import Path

CONFIG_FILE = 'config.ini'

def initialize_runtime_fontconfig():
    """
    为打包的库在运行时配置 fontconfig。
    """
    if platform.system() != "Linux":
        return

    if getattr(sys, 'frozen', False):
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Nuitka 将打包的 .so 文件放在一个子目录中
            lib_dir = os.path.join(base_dir, "_internal")
            if os.path.exists(lib_dir):
                # 添加到库搜索路径
                current_ld_path = os.environ.get('LD_LIBRARY_PATH', '')
                os.environ['LD_LIBRARY_PATH'] = f"{lib_dir}:{current_ld_path}"
            
            # 生成最小化的 fonts.conf
            config_file = os.path.join(base_dir, "fonts.conf")
            cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "fontconfig")
            os.makedirs(cache_dir, exist_ok=True)

            xml = f"""<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
    <dir>{base_dir}</dir>
    <cachedir>{cache_dir}</cachedir>
</fontconfig>
"""
            with open(config_file, "w") as f:
                f.write(xml)
            
            os.environ['FONTCONFIG_FILE'] = config_file
            os.environ['FONTCONFIG_PATH'] = base_dir
            
            print(f"[Info] Generated runtime font config: {config_file_path}")
            
        except Exception as e:
            print(f"[Warning] Failed to initialize runtime font config: {e}")

def setup_linux_font():
    """
    实现无感字体配置。
    检查并为用户安装内置字体。如果fc-cache不存在，仅在控制台打印日志，不弹窗，程序继续运行。
    """
    if platform.system() != "Linux":
        return

    font_name = "myfont.otf"
    font_dir = Path.home() / ".fonts"
    font_path_in_system = font_dir / font_name

    if font_path_in_system.exists():
        return

    # --- MODIFIED: 添加了编码错误容错处理 ---
    try:
        print("首次运行，正在为当前用户配置中文字体...")
    except UnicodeEncodeError:
        print("First run, configuring Chinese font for the current user...")

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        source_font_path = Path(sys._MEIPASS) / font_name
    else:
        source_font_path = Path(__file__).parent / font_name

    if not source_font_path.exists():
        # --- MODIFIED: 添加了编码错误容错处理 ---
        try:
            print(f"错误：内置字体文件 '{font_name}' 未找到！打包可能已损坏。")
        except UnicodeEncodeError:
            print(f"Error: Built-in font file '{font_name}' not found! The package may be corrupted.")
        return

    try:
        font_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(source_font_path, font_path_in_system)
        # --- MODIFIED: 添加了编码错误容错处理 ---
        try:
            print(f"字体已复制到: {font_path_in_system}")
        except UnicodeEncodeError:
            print(f"Font copied to: {font_path_in_system}")

        # ---- MODIFIED: 最终的无感处理逻辑 ----
        if shutil.which('fc-cache'):
            # --- MODIFIED: 添加了编码错误容错处理 ---
            try:
                print("正在刷新字体缓存并重启程序...")
            except UnicodeEncodeError:
                print("Refreshing font cache and restarting the program...")
            os.system('fc-cache -f -v > /dev/null 2>&1') # 静默执行
            python_executable = sys.executable
            script_args = sys.argv
            os.execv(python_executable, [python_executable] + script_args)
        else:
            # --- MODIFIED: 将整个中文警告块添加了编码错误容错处理 ---
            try:
                print("\n--- 字体配置警告 ---")
                print("中文字体已为您配置完成, 但系统缺少 'fontconfig' 工具包。")
                print("这可能导致新字体在您下次登录系统前无法生效。")
                print("要立即生效, 可尝试手动安装: sudo apt-get install fontconfig (Debian/Ubuntu) 或 sudo yum install fontconfig (CentOS/RHEL)。")
                print("---------------------\n")
            except UnicodeEncodeError:
                print("\n--- Font Configuration Warning ---")
                print("Chinese font has been configured, but the 'fontconfig' package is missing.")
                print("This may prevent the new font from taking effect until you log in next time.")
                print("To apply immediately, you can try to install it manually: sudo apt-get install fontconfig (Debian/Ubuntu) or sudo yum install fontconfig (CentOS/RHEL).")
                print("---------------------\n")
            # 不弹窗，不中断，直接让程序继续运行

    except Exception as e:
        # --- MODIFIED: 添加了编码错误容错处理 ---
        try:
            print(f"自动配置字体时发生非致命错误: {e}")
        except UnicodeEncodeError:
            print(f"A non-fatal error occurred during automatic font configuration: {e}")
                
class LogDownloaderApp:
    def __init__(self, master):
        self.master = master
        self.config = configparser.ConfigParser()

        self.include_bag = tk.BooleanVar(value=False)
        self.include_core = tk.BooleanVar(value=False)

        self.stop_event = threading.Event()

        self.load_config()

        self.device_log_state = {
            'progress': 0, 'speed': 0.0, 'eta': 'N/A', 'total_size': 0.0, 'downloaded_size': 0.0
        }
        self.schedule_log_state = {
            'progress': 0, 'speed': 0.0, 'eta': 'N/A', 'total_size': 0.0, 'downloaded_size': 0.0
        }

        self.download_queue = queue.Queue()
        self.ui_update_queue = queue.Queue()
        self.stop_threads = False
        self.current_client = None
        self.current_sftp = None
        self.tar_filename = None

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self.style = ttk.Style()
        self.create_widgets()

        # 动态设置全局字体
        default_font_family = "Source Han Sans SC" if platform.system() == "Linux" else "Microsoft YaHei"
        font_config = (default_font_family, 9)

        self.style.configure('.', font=font_config)
        self.log_display.configure(font=font_config)

        self.ui_update_thread = threading.Thread(target=self.ui_update_thread_func, daemon=True)
        self.ui_update_thread.start()

        self.download_thread = threading.Thread(target=self.download_thread_func, daemon=True)
        self.download_thread.start()

        self.update_defaults()

    def create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=BOTH, expand=YES)

        left_panel = ttk.Frame(main_frame, padding="5")
        left_panel.pack(side=LEFT, fill=Y, expand=NO)

        upper_left = ttk.Frame(left_panel)
        upper_left.pack(side=TOP, fill=Y, expand=YES)

        # CORRECTED: Labelframe
        log_type_frame = ttk.Labelframe(upper_left, text="日志类型", padding="5")
        log_type_frame.pack(fill=X, pady=5)

        self.log_type = tk.StringVar(value="device")
        ttk.Radiobutton(log_type_frame, text="设备日志", variable=self.log_type, value="device",
                        command=self.update_defaults).pack(side=LEFT, padx=5)
        ttk.Radiobutton(log_type_frame, text="调度日志", variable=self.log_type, value="schedule",
                        command=self.update_defaults).pack(side=LEFT, padx=5)

        # CORRECTED: Labelframe
        conn_frame = ttk.Labelframe(upper_left, text="连接详情", padding="5")
        conn_frame.pack(fill=X, pady=5)

        labels = ["IP地址:", "用户名:", "密码:", "日志目录:", "日志时间(分钟):"]
        self.entries = []
        for i, label in enumerate(labels):
            ttk.Label(conn_frame, text=label).grid(row=i, column=0, sticky=E, padx=2, pady=2)
            entry = ttk.Entry(conn_frame, width=25)
            entry.grid(row=i, column=1, padx=2, pady=2)
            self.entries.append(entry)
        self.ip_entry, self.username_entry, self.password_entry, self.log_dir_entry, self.minutes_entry = self.entries

        button_frame = ttk.Frame(upper_left)
        button_frame.pack(fill=X, pady=5)

        self.download_button = ttk.Button(button_frame, text="开始下载", command=self.add_download_task,
                                          style='success.TButton', width=12)
        self.download_button.pack(side=LEFT, padx=2)

        self.stop_button = ttk.Button(button_frame, text="停止下载", command=self.stop_download_process, state=DISABLED,
                                      style='danger.TButton', width=12)
        self.stop_button.pack(side=LEFT, padx=2)

        meter_frame = ttk.Frame(left_panel, padding="5")
        meter_frame.pack(side=BOTTOM, fill=X, expand=NO)

        self.meter = ttk.Meter(
            meter_frame, metersize=180, padding=5, amountused=0,
            metertype="full", subtext="下载进度", interactive=False
        )
        self.meter.pack(side=LEFT, padx=10, pady=10)

        right_panel = ttk.Frame(main_frame, padding="5")
        right_panel.pack(side=LEFT, fill=BOTH, expand=YES)

        top_right_frame = ttk.Frame(right_panel)
        top_right_frame.pack(side=TOP, fill=X, pady=5)

        # CORRECTED: Labelframe
        info_frame = ttk.Labelframe(top_right_frame, text="下载信息", padding="5")
        info_frame.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))

        info_labels = ["下载速度:", "预计时间:", "总大小:", "已下载:"]
        self.info_vars = [tk.StringVar() for _ in range(4)]
        for i, (label, var) in enumerate(zip(info_labels, self.info_vars)):
            ttk.Label(info_frame, text=label).grid(row=i, column=0, sticky=W, padx=2, pady=1)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky=W, padx=2, pady=1)

        # CORRECTED: Labelframe
        self.options_frame = ttk.Labelframe(top_right_frame, text="下载选项", padding="5")
        self.options_frame.pack(side=LEFT, fill=Y, padx=(5, 0))

        self.bag_checkbox = ttk.Checkbutton(
            self.options_frame, text="包含bag数据", variable=self.include_bag,
            command=self.save_download_options
        )
        self.bag_checkbox.pack(anchor=W, padx=5, pady=5)

        self.core_checkbox = ttk.Checkbutton(
            self.options_frame, text="包含core日志", variable=self.include_core,
            command=self.save_download_options
        )
        self.core_checkbox.pack(anchor=W, padx=5, pady=5)

        # CORRECTED: Labelframe
        log_frame = ttk.Labelframe(right_panel, text="日志信息", padding="5")
        log_frame.pack(fill=BOTH, expand=YES)

        self.log_display = tk.Text(log_frame, wrap="word", width=50, height=15)
        self.log_display.pack(side=LEFT, fill=BOTH, expand=YES)
        self.log_display.config(state=tk.DISABLED)

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_display.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.log_display.configure(yscrollcommand=scrollbar.set)

        self.ignore_errors = [
            "file changed as we read it", "文件在读取时被更改", "在我们读入文件时文件发生了变化",
            "无法 stat: 没有那个文件或目录", "No such file or directory", "Broken pipe"
        ]

    def append_log(self, message):
        self.log_display.config(state=tk.NORMAL)
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S] ")
        self.log_display.insert(tk.END, timestamp + message + "\n")
        self.log_display.see(tk.END)
        self.log_display.config(state=tk.DISABLED)

    def connect_ssh(self, ip, username, password):
        self.append_log(f"正在连接IP:{ip}服务器...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, username=username, password=password, timeout=10)
            self.append_log("SSH连接已建立。")
            self.current_client = client
            return client
        except Exception as e:
            error_details = str(e)
            self.append_log(f"SSH连接错误: {error_details}")

            error_message = (
                f"错误详情: {error_details}\n\n"
                "请检查以下可能的原因：\n"
                "1. IP地址、用户名或密码是否正确。\n"
                "2. 目标服务器的网络是否可达 (例如，ping IP)。\n"
                "3. 防火墙是否阻止了SSH端口 (默认为22)。\n"
                "4. 用户账号是否被授权远程登录。\n"
                "5. 目标服务器上的SSH服务是否正在运行。"
            )
            messagebox.showerror("SSH 连接失败", error_message)
            return None

    def add_download_task(self):
        self.reset_download_info()
        self.stop_event.clear()

        self.download_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)

        task_details = self.prepare_download_details()
        self.download_queue.put(task_details)

        log_type_name = '设备日志' if self.log_type.get() == 'device' else '调度日志'
        self.append_log(f"已将{log_type_name}下载任务添加到队列中。")

        if self.log_type.get() == 'device':
            bag_status = "包含" if self.include_bag.get() else "排除"
            core_status = "包含" if self.include_core.get() else "排除"
            self.append_log(f"下载选项 - bag数据: {bag_status}, core日志: {core_status}")

        self.save_config()

    def stop_download_process(self):
        self.append_log("用户请求停止下载...")
        self.stop_event.set()
        self.stop_button.config(state=DISABLED)

    def restore_button_states(self):
        self.download_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def prepare_download_details(self):
        return (self.ip_entry.get(), self.username_entry.get(), self.password_entry.get(),
                self.log_dir_entry.get(), int(self.minutes_entry.get()), self.log_type.get())

    def download_thread_func(self):
        while not self.stop_threads:
            try:
                task = self.download_queue.get(timeout=1)
                if task:
                    self.executor.submit(self.download_logs, task)
            except queue.Empty:
                continue
            except Exception as e:
                self.append_log(f"下载线程错误: {str(e)}")

    def download_logs(self, task_details):
        ip, username, password, log_dir, minutes, log_type = task_details
        sftp = None
        client = None

        try:
            if self.stop_event.is_set():
                self.append_log("下载在开始前被取消。")
                return

            client = self.connect_ssh(ip, username, password)
            if client is None:
                return

            find_command, tar_file_path = self.get_find_command(log_type, log_dir, minutes)

            self.append_log(f"执行打包命令: {find_command}")
            self.append_log("创建归档文件中，请耐心等待...")

            stdin, stdout, stderr = client.exec_command(find_command)

            sftp = client.open_sftp()
            self.current_sftp = sftp

            last_size = 0
            while not stdout.channel.exit_status_ready():
                if self.stop_event.is_set():
                    self.append_log("打包过程中断...")
                    client.exec_command(f"pkill -f '{tar_file_path}'")
                    return
                try:
                    current_size = sftp.stat(tar_file_path).st_size
                    if current_size != last_size:
                        self.update_total_size(current_size, log_type)
                        last_size = current_size
                except FileNotFoundError:
                    pass
                time.sleep(1)

            exit_status = stdout.channel.recv_exit_status()
            error_output = stderr.read().decode()

            critical_errors = self.get_critical_errors(error_output)
            if critical_errors:
                self.append_log(f"打包错误: {'; '.join(critical_errors)}")
                return

            if self.stop_event.is_set(): return

            self.append_log("归档文件创建完成，准备开始下载。")
            final_size = sftp.stat(tar_file_path).st_size
            self.update_total_size(final_size, log_type)

            if not self.tar_filename:
                self.tar_filename = self.get_save_filename()
            if not self.tar_filename:
                self.append_log("用户取消了下载操作。")
                return

            asyncio.run(self.async_download_file(sftp, tar_file_path, self.tar_filename, log_type))

        except Exception as e:
            if not self.stop_event.is_set():
                self.append_log(f"下载流程错误: {str(e)}")
        finally:
            if sftp:
                sftp.close()
            if client:
                client.close()
            self.master.after(0, self.restore_button_states)

    def get_find_command(self, log_type, log_dir, minutes):
        if log_type == "device":
            base_dir = "/opt"
            tar_file_path = "/tmp/log.tar.gz"

            find_parts = []

            log_prune_paths = ['./log/bag']
            if not self.include_bag.get():
                log_prune_paths.append('./log/bslam/bag')
            if not self.include_core.get():
                log_prune_paths.append('./log/core')

            log_prune_str = ' -o '.join([f'-path "{path}" -prune' for path in log_prune_paths])
            find_log_cmd = f'find ./log {log_prune_str} -o -type f -mmin -{minutes} -print0 2>/dev/null'
            find_parts.append(find_log_cmd)

            if self.include_bag.get():
                find_drive_recoder_cmd = f'find ./drive_recoder -type f -mmin -{minutes} -print0 2>/dev/null'
                find_parts.append(find_drive_recoder_cmd)

            combined_finds = '; '.join(find_parts)
            command = (
                f'cd {base_dir} && '
                f'rm -f {tar_file_path} && '
                f'({combined_finds}) | '
                f'tar --null -czf {tar_file_path} --files-from -'
            )
            return command, tar_file_path
        else:
            tar_file_path = os.path.join(log_dir, "log.tar.gz")
            command = (
                f'cd {log_dir} && '
                f'rm -f {tar_file_path} && '
                f'find ./ -type f -mmin -{minutes} '
                f'-not -path "./snap/*" '
                f'-not -name "log.tar.gz" '
                f'-print0 | tar --null -czf {tar_file_path} --files-from -'
            )
            return command, tar_file_path

    def get_critical_errors(self, error_output):
        return [line for line in error_output.splitlines() if
                not any(ignore_error in line for ignore_error in self.ignore_errors) and line.strip() != ""]

    async def async_download_file(self, sftp, remote_path, local_path, log_type):
        try:
            total_size = sftp.stat(remote_path).st_size
            self.append_log(f"开始下载: 从 {remote_path} 到本地: {local_path}")

            start_time = time.time()
            last_update_time = start_time
            update_interval = 0.5

            def update_progress(transferred, total):
                if self.stop_event.is_set():
                    raise InterruptedError("Download cancelled by user.")

                nonlocal last_update_time
                current_time = time.time()
                if current_time - last_update_time < update_interval: return

                last_update_time = current_time
                elapsed_time = current_time - start_time
                progress = (transferred / total) * 100
                speed = transferred / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                remaining_bytes = total - transferred
                eta = (remaining_bytes / (speed * 1024 * 1024)) if speed > 0 else float('inf')

                self.ui_update_queue.put({
                    'log_type': log_type,
                    'state': {'progress': progress, 'speed': speed,
                              'eta': f"{int(eta)} 秒" if eta != float('inf') else "N/A",
                              'total_size': total / (1024 * 1024), 'downloaded_size': transferred / (1024 * 1024)}
                })

            await asyncio.to_thread(sftp.get, remote_path, local_path, update_progress)

            if self.stop_event.is_set(): return

            self.append_log("文件下载完成。")
            if os.path.exists(local_path) and os.path.getsize(local_path) == total_size:
                self.ui_update_queue.put({
                    'log_type': log_type,
                    'state': {'progress': 100, 'total_size': total_size / (1024 * 1024),
                              'downloaded_size': total_size / (1024 * 1024)}
                })
                self.current_client.exec_command(f'rm -f {remote_path}')
                self.append_log(f"已删除远程临时压缩包文件: {remote_path}")
            else:
                self.append_log("警告: 本地文件大小与远程文件不匹配。远程文件未删除。")

        except InterruptedError:
            self.append_log("SFTP下载已中断。")
            if os.path.exists(local_path):
                try:
                    os.remove(local_path)
                    self.append_log(f"已删除本地不完整文件: {local_path}")
                except OSError as e:
                    self.append_log(f"删除本地文件失败: {e}")
        except Exception as e:
            if not self.stop_event.is_set():
                self.append_log(f"SFTP下载错误: {e}")

    def ui_update_thread_func(self):
        while not self.stop_threads:
            try:
                update_info = self.ui_update_queue.get(timeout=0.1)
                self.master.after(0, self.update_ui, update_info)
            except queue.Empty:
                continue

    def update_ui(self, update_info):
        log_type = update_info['log_type']
        state = update_info['state']

        if log_type == "device":
            self.device_log_state.update(state)
        else:
            self.schedule_log_state.update(state)
        self.update_display()

    def on_closing(self):
        if messagebox.askokcancel("退出", "确定要退出吗?"):
            self.stop_event.set()
            self.save_config()
            self.stop_threads = True
            if self.download_thread.is_alive():
                self.download_thread.join(timeout=2)
            self.master.quit()
            self.master.destroy()

    def reset_download_info(self):
        state = self.device_log_state if self.log_type.get() == "device" else self.schedule_log_state
        state.update({'progress': 0, 'speed': 0.0, 'eta': 'N/A', 'total_size': 0.0, 'downloaded_size': 0.0})
        self.tar_filename = None
        self.update_display()
        self.meter.configure(amountused=0)

    def update_display(self):
        state = self.device_log_state if self.log_type.get() == "device" else self.schedule_log_state
        progress = round(state['progress'])
        self.meter.configure(amountused=progress)
        self.info_vars[0].set(f"{state['speed']:.2f} MB/s")
        self.info_vars[1].set(state['eta'])
        self.info_vars[2].set(f"{state['total_size']:.2f} MB")
        self.info_vars[3].set(f"{state['downloaded_size']:.2f} MB")

    def load_config(self):
        try:
            if not os.path.exists(CONFIG_FILE):
                self.set_default_config()
            with open(CONFIG_FILE, 'r', encoding='utf-8') as configfile:
                self.config.read_file(configfile)
        except Exception as e:
            self.append_log(f"读取配置文件时出错: {str(e)}")
            self.set_default_config()

    def set_default_config(self):
        self.config['device'] = {
            'ip': '', 'username': 'root', 'password': 'oelinux123',
            'log_dir': '/opt/', 'minutes': '10',
            'include_bag': 'False', 'include_core': 'False'
        }
        self.config['schedule'] = {
            'ip': '', 'username': 'xwrcs', 'password': '123456',
            'log_dir': '/home/xwrcs/', 'minutes': '10'
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as configfile:
            self.config.write(configfile)

    def save_config(self):
        log_type = self.log_type.get()
        self.config[log_type] = {
            'ip': self.ip_entry.get(), 'username': self.username_entry.get(),
            'password': self.password_entry.get(), 'log_dir': self.log_dir_entry.get(),
            'minutes': self.minutes_entry.get()
        }
        if log_type == 'device':
            self.config[log_type]['include_bag'] = str(self.include_bag.get())
            self.config[log_type]['include_core'] = str(self.include_core.get())
        with open(CONFIG_FILE, 'w', encoding='utf-8') as configfile:
            self.config.write(configfile)

    def save_download_options(self):
        if self.log_type.get() == 'device':
            self.save_config()

    def update_defaults(self):
        log_type = self.log_type.get()
        self.username_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)
        self.log_dir_entry.config(state=tk.NORMAL)

        config_section = self.config[log_type]

        for entry, key in zip([self.ip_entry, self.username_entry, self.password_entry, self.minutes_entry],
                              ['ip', 'username', 'password', 'minutes']):
            entry.delete(0, tk.END)
            entry.insert(0, config_section.get(key, ''))

        if log_type == "device":
            self.include_bag.set(config_section.getboolean('include_bag', False))
            self.include_core.set(config_section.getboolean('include_core', False))
            self.username_entry.config(state=tk.DISABLED)
            self.password_entry.config(show='*', state=tk.DISABLED)

            self.log_dir_entry.delete(0, tk.END)
            self.log_dir_entry.insert(0, "/opt/")
            self.log_dir_entry.config(state=tk.DISABLED)

            self.toggle_device_options_visibility(True)
        else:
            self.log_dir_entry.delete(0, tk.END)
            self.log_dir_entry.insert(0, config_section.get('log_dir', ''))
            self.password_entry.config(state=tk.NORMAL, show='')
            self.toggle_device_options_visibility(False)
        self.update_display()

    def toggle_device_options_visibility(self, show):
        if show:
            self.options_frame.pack(side=LEFT, fill=Y, padx=(5, 0))
        else:
            self.options_frame.pack_forget()

    def update_total_size(self, size, log_type):
        state = self.device_log_state if log_type == "device" else self.schedule_log_state
        state['total_size'] = size / (1024 * 1024)
        self.master.after(0, self.update_display)

    def get_save_filename(self):
        return filedialog.asksaveasfilename(
            defaultextension=".tar.gz",
            filetypes=[("Tar Gz 文件", "*.tar.gz")]
        )

def get_random_theme():
    light_themes = [
        "cosmo", "flatly", "journal", "litera", "lumen", "minty",
        "pulse", "sandstone", "united", "yeti", "morph", "simplex", "cerculean"
    ]
    dark_themes = ["cyborg", "darkly", "solar", "superhero", "vapor"]
    return random.choice(light_themes + dark_themes)

def get_img_base64(base64_icon):
    icon_data = base64.b64decode(base64_icon)
    return PhotoImage(data=icon_data)

def get_scaling_factor(window):
    dpi = window.winfo_fpixels('1i')
    base_dpi = 96
    return dpi / base_dpi

def main():
    initialize_runtime_fontconfig()
    # 调用字体设置函数
    setup_linux_font()

    base64_icon = """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"""

    random_theme = get_random_theme()
    window = ttk.Window(themename=random_theme)
    window.title("日志下载工具 (V1.8.0)")

    scaling_factor = get_scaling_factor(window)

    window_width = int(680 * scaling_factor)
    window_height = int(560 * scaling_factor)
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    position_top = int(screen_height / 2 - window_height / 2)
    position_right = int(screen_width / 2 - window_width / 2)
    window.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')
    window.resizable(False, False)

    window.iconphoto(False, get_img_base64(base64_icon))

    main_app = LogDownloaderApp(window)
    window.protocol("WM_DELETE_WINDOW", main_app.on_closing)
    window.mainloop()


if __name__ == "__main__":
    main()
