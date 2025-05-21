import sys
import os
import configparser
import webbrowser  # For potential future use, not strictly needed for now
import ctypes  # For icon setting on Windows if needed directly

# Attempt to import PyQt5 and provide a user-friendly message if not found
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QCheckBox, QTextEdit, QMessageBox,
        QSystemTrayIcon, QMenu, QAction, QStyle
    )
    from PyQt5.QtGui import QIcon, QDesktopServices
    from PyQt5.QtCore import QThread, pyqtSignal, QTimer, QSettings, QUrl
except ImportError:
    # Fallback for QMessageBox if QApplication can't be created
    def show_critical_error_fallback(title, message):
        # This is a very basic fallback, might not always work if tkinter isn't available either
        # but it's better than a silent console crash for a GUI app.
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw() # Hide the main tkinter window
            messagebox.showerror(title, message)
            root.destroy()
        except ImportError:
            # If tkinter also fails, print to console as last resort
            print(f"CRITICAL ERROR: {title}\n{message}\n\nPlease install the required PyQt5 module.")

    show_critical_error_fallback(
        "模块缺失错误",
        "运行此应用程序需要 PyQt5 模块，但未找到。\n\n"
        "请通过 pip 安装 PyQt5:\n"
        "pip install PyQt5\n\n"
        "安装后请重新运行程序。"
    )
    sys.exit(1)


# Import functions from DTS_AutoLogin.py
# Assuming DTS_AutoLogin.py is in the same directory
try:
    import DTS_AutoLogin
except ImportError:
    # This allows running the script from a different CWD if DTS_AutoLogin.py is discoverable
    # For simplicity, we assume it's in the same directory or Python path
    print("Error: DTS_AutoLogin.py not found. Make sure it's in the same directory or Python path.")
    sys.exit(1)

# For Windows Taskbar Icon (might be needed if QIcon alone isn't enough for .exe)
if os.name == 'nt':
    myappid = 'mycompany.myproduct.subproduct.version'  # arbitrary string
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

# Registry key for startup
STARTUP_REG_KEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
APP_NAME_REG = "CampusNetLoginGUI"


class NetworkLoginWorker(QThread):
    """
    Worker thread for network checking and login attempts.
    Emits signals to update the GUI.
    """
    status_update = pyqtSignal(str)
    login_result = pyqtSignal(bool, str)  # success (bool), message (str)

    def __init__(self, settings_func, login_func):
        super().__init__()
        self.get_settings = settings_func
        self.perform_login_attempt = login_func
        self._is_running = True
        self.current_session = None

    def run(self):
        #self.status_update.emit("NetworkLoginWorker.run() 方法开始执行。")
        try:
            #self.status_update.emit("创建 requests.Session()...")
            self.current_session = DTS_AutoLogin.requests.Session()
            #self.status_update.emit("requests.Session() 创建成功。")

            while self._is_running:
                self.status_update.emit("循环开始：正在检测网络连接...")
                try:
                    # Use a reliable, fast-responding HTTPS site for connection check
                    self.current_session.get("https://www.baidu.com", timeout=5)
                    self.status_update.emit("网络已连接。将在10秒后再次检测。")
                    # If connected, we don't auto-login unless specifically triggered or state changes.
                except DTS_AutoLogin.requests.exceptions.RequestException as net_err:
                    self.status_update.emit(f"网络检测请求错误: {net_err}")
                    self.status_update.emit("网络未连接。尝试自动登录...")
                    current_settings = self.get_settings()
                    if not current_settings:
                        self.status_update.emit("错误：无法加载配置以进行自动登录。")
                        self.login_result.emit(False, "无法加载配置")
                    else:
                        # Use the existing session for the login attempt
                        self.status_update.emit("尝试执行登录操作...")
                        result = self.perform_login_attempt(current_settings, self.current_session)
                        self.status_update.emit(f"登录操作完成，结果: {result.get('success', False)}")
                        self.login_result.emit(result.get("success", False),
                                               result.get("message", "登录尝试完成，但结果未知。"))
                except Exception as e_inner_loop: # Catch other exceptions inside the loop
                    self.status_update.emit(f"工作线程循环内部发生错误: {e_inner_loop}")
                    import traceback
                    self.status_update.emit(traceback.format_exc())


                # Wait for 10 seconds before the next check
                if self._is_running:  # Check if still running before sleeping
                    self.status_update.emit("线程休眠10秒...")
                    self.sleep(10)  # Sleep for 10 seconds
                    self.status_update.emit("线程唤醒。")

            self.status_update.emit("工作线程循环结束。")
        except Exception as e_run:
            self.status_update.emit(f"NetworkLoginWorker.run() 方法发生严重错误: {e_run}")
            import traceback
            self.status_update.emit(traceback.format_exc()) # Print full stack trace
        finally:
            if self.current_session:
                self.status_update.emit("关闭 requests.Session()...")
                self.current_session.close()
                self.status_update.emit("requests.Session() 已关闭。")
            self.status_update.emit("NetworkLoginWorker.run() 方法执行完毕。")

    def stop(self):
        self._is_running = False
        self.status_update.emit("正在停止网络监控线程...") # Original message
        self.status_update.emit("NetworkLoginWorker.stop() 被调用。") # Added log
        self.wait()  # Wait for the thread to finish


class CampusLoginApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Determine application path
        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle/exe
            application_path = os.path.dirname(sys.executable)
        else:
            # If the application is run as a .py script
            application_path = os.path.dirname(os.path.abspath(__file__))

        # Assume DTS_AutoLogin.CONFIG_FILE_NAME is just the filename, e.g., "config.ini"
        # If it might contain path components, this needs adjustment or clarification.
        # For now, we assume it's a simple filename.
        config_filename = DTS_AutoLogin.CONFIG_FILE_NAME
        if os.path.isabs(config_filename):
            # If CONFIG_FILE_NAME is already an absolute path, use it directly.
            # This might be an edge case depending on how DTS_AutoLogin.CONFIG_FILE_NAME is defined.
            self.settings_file_path = config_filename
            # Log a warning if this happens, as it might not be the intended behavior
            # print(f"Warning: DTS_AutoLogin.CONFIG_FILE_NAME ('{config_filename}') is an absolute path. Using it directly.")
        else:
            # Construct absolute path for the config file in the application's directory
            self.settings_file_path = os.path.join(application_path, config_filename)

        self.current_settings = {}
        self.init_ui()
        self.load_settings_to_ui()
        self.check_startup_status()

        self.worker_thread = None
        self.start_worker() # Call start_worker after all members are initialized

    def init_ui(self):
        #self.append_status_message("CampusLoginApp.init_ui() 开始...") # New log
        self.setWindowTitle("校园网自动登录")
        # Attempt to set window icon
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Credentials
        form_layout = QVBoxLayout()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(QLabel("用户名:"))
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(QLabel("密码:"))
        form_layout.addWidget(self.password_input)

        main_layout.addLayout(form_layout)

        # Buttons
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("保存配置")
        self.save_button.clicked.connect(self.save_settings_from_ui)
        self.login_button = QPushButton("立即登录")
        self.login_button.clicked.connect(self.manual_login_attempt)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.login_button)
        main_layout.addLayout(button_layout)

        # Startup Checkbox
        self.startup_checkbox = QCheckBox("开机自启动 (隐藏到托盘)")
        self.startup_checkbox.stateChanged.connect(self.toggle_startup)
        main_layout.addWidget(self.startup_checkbox)

        # Status Area
        self.status_area = QTextEdit()
        self.status_area.setReadOnly(True)
        main_layout.addWidget(QLabel("状态与日志:"))
        main_layout.addWidget(self.status_area)

        self.resize(400, 300)
        self.create_tray_icon()
        #self.append_status_message("CampusLoginApp.init_ui() 完成。") # New log

    def get_current_settings_for_worker(self):
        self.append_status_message("CampusLoginApp.get_current_settings_for_worker() 被调用。") # New log
        # This function is passed to the worker to get fresh settings
        # Return a copy to prevent modification by the worker if it's a mutable type
        return self.current_settings.copy() if isinstance(self.current_settings, dict) else self.current_settings

    def start_worker(self):
        #self.append_status_message("CampusLoginApp.start_worker() 被调用。")
        try:
            if self.worker_thread is None or not self.worker_thread.isRunning():
                #self.append_status_message("创建 NetworkLoginWorker 实例...")
                self.worker_thread = NetworkLoginWorker(
                    settings_func=self.get_current_settings_for_worker,
                    login_func=DTS_AutoLogin.attempt_DTS_AutoLogin # Pass the actual function
                )
                #self.append_status_message("连接信号槽...")
                self.worker_thread.status_update.connect(self.append_status_message)
                self.worker_thread.login_result.connect(self.handle_login_result)
                self.append_status_message("启动线程 (worker_thread.start())...")
                self.worker_thread.start()
                self.append_status_message("网络监控和自动登录线程已成功请求启动。") # Changed message slightly
            else:
                self.append_status_message("工作线程已在运行，未重新启动。")
        except Exception as e:
            self.append_status_message(f"CampusLoginApp.start_worker() 发生严重错误: {e}")
            import traceback
            self.append_status_message(traceback.format_exc()) # Print full stack trace


    def stop_worker(self):
        self.append_status_message("CampusLoginApp.stop_worker() 被调用。") # New log
        if self.worker_thread and self.worker_thread.isRunning():
            self.append_status_message("请求停止工作线程...") # New log
            self.worker_thread.stop()
            self.append_status_message("工作线程停止请求已发送。") # New log
            # self.worker_thread = None # Worker calls self.wait(), so it should clean up.
        else:
            self.append_status_message("工作线程未运行或不存在，无需停止。") # New log


    def append_status_message(self, message):
        # Ensure this method is robust, as it's called from threads
        if hasattr(self, 'status_area') and self.status_area is not None: # Check if status_area exists
            self.status_area.append(message)
            self.status_area.ensureCursorVisible()  # Scroll to bottom
        else:
            # Fallback if status_area is not yet initialized or available
            print(f"LOG (status_area not ready): {message}")


    def handle_login_result(self, success, message):
        self.append_status_message(f"登录尝试结果: {'成功' if success else '失败'}")
        # The message from attempt_DTS_AutoLogin can be multi-line and detailed.
        # We might want to parse it or display it more selectively.
        # For now, append the core message.
        if message:
            # Split message by newlines and append each part for better readability
            for line in message.splitlines():
                if line.strip():  # Avoid empty lines
                    self.append_status_message(f"  {line.strip()}")

    def load_settings_to_ui(self):
        config = configparser.ConfigParser()
        loaded_settings = {}
        try:
            if os.path.exists(self.settings_file_path):
                config.read(self.settings_file_path, encoding='utf-8') # Specify encoding
                if 'Settings' in config:
                    loaded_settings['username'] = config['Settings'].get('username', '')
                    loaded_settings['password'] = config['Settings'].get('password', '')
                    # Load any other settings if needed
                    for key in config['Settings']:
                        if key not in ['username', 'password']:
                            loaded_settings[key] = config['Settings'][key]
                    self.append_status_message(f"配置已从 {self.settings_file_path} 加载。")
                else:
                    self.append_status_message(f"配置文件 {self.settings_file_path} 中缺少 'Settings' 部分。将使用默认值。")
                    # Create 'Settings' section if missing, and prepare to save default structure
                    config['Settings'] = {'username': '', 'password': ''}
                    with open(self.settings_file_path, 'w', encoding='utf-8') as configfile:
                        config.write(configfile)
                    self.append_status_message(f"已创建带有默认 'Settings' 部分的配置文件: {self.settings_file_path}")
                    loaded_settings = {'username': '', 'password': ''}

            else:
                self.append_status_message(f"配置文件 {self.settings_file_path} 不存在。将创建新文件并使用默认值。")
                config['Settings'] = {
                    'username': '',
                    'password': ''
                }
                with open(self.settings_file_path, 'w', encoding='utf-8') as configfile:
                    config.write(configfile)
                self.append_status_message(f"已创建新的配置文件: {self.settings_file_path}")
                loaded_settings = {'username': '', 'password': ''}

        except configparser.Error as e:
            self.append_status_message(f"读取配置文件 {self.settings_file_path} 时出错: {e}。将使用默认值。")
            # Fallback to default empty settings in case of parsing error
            loaded_settings = {'username': '', 'password': ''}
            # Optionally, try to create a fresh default config if parsing failed badly
            try:
                config = configparser.ConfigParser() # Fresh parser
                config['Settings'] = {'username': '', 'password': ''}
                with open(self.settings_file_path, 'w', encoding='utf-8') as configfile: # Overwrite corrupted
                    config.write(configfile)
                self.append_status_message(f"已用默认值覆盖/创建配置文件: {self.settings_file_path}，因为发生解析错误。")
            except Exception as e_create:
                self.append_status_message(f"尝试创建默认配置文件失败: {e_create}")

        except Exception as e: # Catch other potential errors during file I/O
            self.append_status_message(f"加载或创建配置文件时发生未知错误: {e}。将使用默认值。")
            loaded_settings = {'username': '', 'password': ''}


        self.current_settings = loaded_settings
        self.username_input.setText(self.current_settings.get('username', ''))
        self.password_input.setText(self.current_settings.get('password', ''))
        # self.append_status_message("配置已加载到UI。") # Message is now more specific above

    def save_settings_from_ui(self):
        config = configparser.ConfigParser()
        new_settings_for_config_object = {}
        try:
            # Read existing config to preserve other sections or settings not managed by UI
            # This is important if the config file might have other data.
            if os.path.exists(self.settings_file_path):
                config.read(self.settings_file_path, encoding='utf-8')

            if 'Settings' not in config:
                config['Settings'] = {}

            # Update settings from UI
            ui_username = self.username_input.text()
            ui_password = self.password_input.text()
            config['Settings']['username'] = ui_username
            config['Settings']['password'] = ui_password
            new_settings_for_config_object['username'] = ui_username
            new_settings_for_config_object['password'] = ui_password

            # Preserve other existing settings from self.current_settings
            # that are not directly from the UI input fields being saved now.
            # This ensures that if self.current_settings had other keys loaded,
            # they are also written back if they are not already in the config object
            # from the read operation.
            for key, value in self.current_settings.items():
                if key not in ['username', 'password']: # Don't overwrite UI values
                    if key not in config['Settings']: # Add if not already present from file read
                        config['Settings'][key] = str(value) # Ensure value is string for configparser
                    new_settings_for_config_object[key] = value


            with open(self.settings_file_path, 'w', encoding='utf-8') as configfile:
                config.write(configfile)

            # Update self.current_settings directly from what was just prepared and saved
            self.current_settings = new_settings_for_config_object.copy()

            self.append_status_message("配置已保存到 " + self.settings_file_path)
            QMessageBox.information(self, "成功", "配置已保存！")
        except Exception as e:
            self.append_status_message(f"保存配置失败: {e}")
            QMessageBox.warning(self, "错误", f"保存配置失败: {e}")

    def manual_login_attempt(self):
        self.append_status_message("手动触发登录...")
        # Use a new session for manual attempt or ensure worker's session is used carefully
        # For simplicity, let's use a one-off session for manual login
        # Or, better, signal the worker to do it if we want to use its session and avoid conflicts

        # Quick manual attempt with new session:
        manual_session = DTS_AutoLogin.requests.Session()
        try:
            current_config = self.get_current_settings_for_worker()
            if not current_config.get('username') or current_config.get('username') == '1':
                QMessageBox.warning(self, "提示", "用户名未配置或为默认值，请先在上方配置并保存。")
                self.append_status_message("手动登录中止：用户名未配置。")
                return

            result = DTS_AutoLogin.attempt_DTS_AutoLogin(current_config, manual_session)
            self.handle_login_result(result.get("success", False), result.get("message", "手动登录尝试完成"))
        finally:
            manual_session.close()

    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            # Fallback system icon
            self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        show_action = QAction("显示/隐藏", self)
        quit_action = QAction("退出", self)
        show_action.triggered.connect(self.toggle_window_visibility)
        quit_action.triggered.connect(self.quit_application)

        tray_menu = QMenu()
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.toggle_window_visibility()

    def toggle_window_visibility(self):
        if self.isVisible():
            self.hide()
            self.append_status_message("窗口已隐藏到系统托盘。")
        else:
            self.show()
            self.activateWindow()
            self.append_status_message("窗口已从系统托盘恢复。")

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "校园网登录助手",
            "应用已最小化到托盘。",
            QSystemTrayIcon.Information,
            2000
        )
        self.append_status_message("窗口关闭操作：隐藏到系统托盘。")

    def quit_application(self):
        self.append_status_message("正在退出应用程序...")
        self.stop_worker()  # Ensure worker thread is stopped
        QApplication.instance().quit()

    def get_startup_path(self):
        # Get the absolute path to the current script (campus_gui.py)
        # If running as a frozen executable (e.g., PyInstaller), sys.executable is the path to the .exe
        if getattr(sys, 'frozen', False):
            return sys.executable
        else:
            # Running as a .py script
            return os.path.abspath(__file__)

    def check_startup_status(self):
        settings = QSettings(STARTUP_REG_KEY, QSettings.NativeFormat)
        app_path_reg = settings.value(APP_NAME_REG)

        current_app_path_for_reg = f'"{sys.executable}" "{self.get_startup_path()}" --minimized'
        # A simpler version if pythonw is reliably in PATH and handles .py files directly
        # current_app_path_for_reg = f'pythonw.exe "{self.get_startup_path()}" --minimized'
        # For .exe, it would be:
        # current_app_path_for_reg = f'"{self.get_startup_path()}" --minimized'

        # Normalize paths for comparison
        normalized_app_path_reg = os.path.normpath(str(app_path_reg)).lower() if app_path_reg else None

        # Construct what the registry value *should* be for the current script/exe
        # If frozen, sys.executable is the exe path.
        # If not frozen, we need python(w).exe + script path.
        if getattr(sys, 'frozen', False):  # Running as EXE
            expected_reg_value = f'"{self.get_startup_path()}" --minimized'
        else:  # Running as PY script
            # This assumes pythonw.exe is preferred for silent startup and is in PATH
            # A more robust way for scripts is to use sys.executable (path to python.exe)
            # and rely on python.exe to run the .py script (though it might show a console briefly).
            # Using pythonw.exe is generally better for GUI apps run at startup.
            expected_reg_value = f'"{sys.executable}" "{os.path.abspath(__file__)}" --minimized'
            # If you are sure pythonw is the target:
            # expected_reg_value = f'pythonw.exe "{os.path.abspath(__file__)}" --minimized'

        normalized_expected_reg_value = os.path.normpath(expected_reg_value).lower()

        if app_path_reg and normalized_app_path_reg == normalized_expected_reg_value:
            self.startup_checkbox.setChecked(True)
            self.append_status_message("检测到已启用开机自启动。")
        else:
            self.startup_checkbox.setChecked(False)
            if app_path_reg:  # If there's a value but it doesn't match, it might be for an old version/path
                self.append_status_message(
                    f"检测到旧的或不匹配的开机自启动项: {app_path_reg}。建议禁用并重新启用以更新路径。")
            else:
                self.append_status_message("检测到未启用开机自启动。")

    def toggle_startup(self, state):
        settings = QSettings(STARTUP_REG_KEY, QSettings.NativeFormat)
        app_executable_path = self.get_startup_path()

        if getattr(sys, 'frozen', False):  # EXE
            # Path for .exe: "C:\path\to\your_app.exe" --minimized
            app_path_for_reg = f'"{app_executable_path}" --minimized'
        else:  # PY script
            # Path for .py: "C:\path\to\pythonw.exe" "C:\path\to\campus_gui.py" --minimized
            # Using sys.executable (path to python.exe/pythonw.exe that is running the script)
            # is generally more robust than hardcoding "pythonw.exe"
            app_path_for_reg = f'"{sys.executable}" "{app_executable_path}" --minimized'

        if state == 2:  # Qt.Checked
            settings.setValue(APP_NAME_REG, app_path_for_reg)
            self.append_status_message(f"已设置开机自启动。路径: {app_path_for_reg}")
        else:  # Qt.Unchecked
            settings.remove(APP_NAME_REG)
            self.append_status_message("已取消开机自启动。")


def main_gui(start_minimized=False):
    app = QApplication(sys.argv)
    # Ensure the app has an icon, especially if packaged.
    # This might be redundant if set on QMainWindow and QSystemTrayIcon, but can help.
    icon_path_main = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
    if os.path.exists(icon_path_main):
        app.setWindowIcon(QIcon(icon_path_main))

    main_win = CampusLoginApp()

    if start_minimized:
        main_win.append_status_message("以最小化模式启动。")
        # Don't show the main window, rely on tray icon.
        # The tray icon is shown in CampusLoginApp.__init__ -> create_tray_icon
        # main_win.hide() # This would hide it if it was shown, but we want to prevent initial show
    else:
        main_win.show()
        main_win.append_status_message("应用程序已启动。")

    sys.exit(app.exec_())


if __name__ == "__main__":
    start_minimized_flag = "--minimized" in sys.argv
    main_gui(start_minimized=start_minimized_flag)
