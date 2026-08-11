from PySide6.QtWidgets import (
    QApplication,
    QMainWindow, 
    QPushButton, 
    QWidget, 
    QVBoxLayout, 
    QLabel, 
    QTableWidget,
    QTableWidgetItem
)
from PySide6.QtCore import (
    QThread,
    Signal
)
import sys
import time

class CounterThread(QThread):
    tick_signal = Signal(int)# 定義一個訊號,tick_signal 會傳出一個int(數字)

    def __init__(self):
        super().__init__()
        self._running = True# 用來控制迴圈要不要繼續跑

    def run(self):
        count = 0
        while self._running:
            count+=1
            self.tick_signal.emit(count)# 把數字"發送"出去
            time.sleep(1)# 模擬耗時的工作(這裡先假裝是監聽邏輯)

    # 自鄧一個"停止"的方法,讓外部可以喊停
    def stop(self):
        self._running = False

def update_label(count):
    """當背景執行續emit訊號時,這個函式會被呼叫,拿到傳來的數字"""
    counter_label.setText(f"計數:{count}")

def start_listening():
    # print("Button clicked!")
    counter_thread.start()
    status_label.setText("狀態:監聽中...")

def stop_listening():
    counter_thread.stop()
    status_label.setText("狀態:已停止...")

# def add_fake_ip():
#     """先用假資料測試表格怎麼加資料,之後這裡會換成真的監聽邏輯"""
#     row_position = table.rowCount()
#     table.insertRow(row_position)

#     # setItem(列, 欄, 內容) — 欄位從 0 開始算
#     table.setItem(row_position, 0, QTableWidgetItem("123.45.67.89"))
#     table.setItem(row_position, 1, QTableWidgetItem("2026-08-11 10:30:00"))
#     table.setItem(row_position, 2, QTableWidgetItem("443"))

app = QApplication(sys.argv)

window = QMainWindow()
window.setWindowTitle("QThread 練習")
window.resize(400, 200)

container = QWidget()
layout = QVBoxLayout()

# 設定標籤
status_label = QLabel("狀態:尚未啟動")
counter_label = QLabel("計數:0")

# 設定按鈕
start_button = QPushButton("開始")
stop_button = QPushButton("停止")

# 布局
layout.addWidget(status_label)
layout.addWidget(counter_label)
layout.addWidget(start_button)
layout.addWidget(stop_button)



# # 建立表格(三欄)
# table = QTableWidget()
# table.setColumnCount(3)
# table.setHorizontalHeaderLabels(["IP位址", "時間", "埠號"])




container.setLayout(layout)
window.setCentralWidget(container)

# 建立執行序物件
counter_thread = CounterThread()

# 把執行序的訊號連接到主視窗的函式
counter_thread.tick_signal.connect(update_label)

# 定義按鈕事件
start_button.clicked.connect(start_listening)
stop_button.clicked.connect(stop_listening)

# app.exec() -> return 0
window.show()
sys.exit(app.exec())


