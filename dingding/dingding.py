import os
import time
import hmac
import json
import base64
import hashlib
import requests
import chinese_calendar as calendar
from urllib.parse import quote_plus
from datetime import datetime

class Messenger:
    def __init__(self, token=os.getenv("DD_ACCESS_TOKEN"), secret=os.getenv("DD_SECRET")):
        """
        初始化方法
        @param token: str, 钉钉机器人访问令牌
        @param secret: str, 钉钉机器人密钥
        """
        self.token = token
        self.secret = secret
        self.URL = "https://oapi.dingtalk.com/robot/send"
        self.headers = {'Content-Type': 'application/json'}
        self.params = {'access_token': self.token}
        self.update_timestamp_and_sign()

        # GPU 参数
        self.total_memory_GB = 24
        self.utilization_thred = 0.6
        self.memory_used_thred = 0.5

        # 时间控制参数
        self.time_range = [('08:20', '11:50'), ('13:10', '17:30')]
        self.last_true_time = {}
        self.time_interval = 30  # 间隔30分钟推送一次

    def send_md(self, message_json, server_ip):
        """
        发送 Markdown 格式的消息到钉钉。
        """
        self.update_timestamp_and_sign()
        if self.should_call_function_during_chinese_workdays(server_ip):
            if not message_json:
                text = f"**服务器IP**: `{server_ip}`\n**状态**: **连接失败**"
                self.send_markdown_to_dingtalk("服务器连接失败", text)
            else:
                content, is_free = self.format_gpu_usage_to_markdown(message_json, server_ip)
                if is_free:
                    self.send_markdown_to_dingtalk("显卡使用情况", content)

    def update_timestamp_and_sign(self):
        """
        更新时间戳和签名。
        """
        self.timestamp = str(round(time.time() * 1000))
        secret_enc = self.secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(self.timestamp, self.secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        self.sign = quote_plus(base64.b64encode(hmac_code))
        self.params['timestamp'] = self.timestamp
        self.params['sign'] = self.sign

    def send_markdown_to_dingtalk(self, title, text):
        """
        构建并通过钉钉发送 Markdown 消息。
        """
        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": text
            }
        }
        try:
            requests.post(url=self.URL, data=json.dumps(data), params=self.params, headers=self.headers)
        except Exception as e:
            print(f"发生错误: {e}")

    def format_gpu_usage_to_markdown(self, message_json, server_ip):
        """
        格式化 GPU 使用信息为 Markdown 文本。
        """
        rows = []
        rows.append(f"**{server_ip}**")
        rows.append("")
        rows.append("| ID | GPU利用率 | 显存使用量 | 用户 |")
        rows.append("|:-------:|:------------:|:----------------:|:------:|")

        is_any_free = False
        for gpu in message_json:
            index = gpu['index']
            utilization = gpu['utilization.gpu']
            memory_used_MB = gpu['memory.used']
            memory_used_GB = memory_used_MB / 1024
            memory_percentage = (memory_used_MB / (self.total_memory_GB * 1024)) * 100

            users = [process['username'] for process in gpu['processes']]
            users_str = ', '.join(set(users)) if users else '-'

            is_free = utilization < 100 * self.utilization_thred and memory_used_MB < (self.total_memory_GB * 1024 * self.memory_used_thred)
            if is_free:
                is_any_free = True
                row = f"| <font color='green'>**{index}**</font> | <font color='green'>**{utilization}%**</font> | <font color='green'>**{memory_used_GB:.1f}GB ({memory_percentage:.0f}%)**</font> | <font color='green'>**{users_str}**</font> |"
            else:
                row = f"| {index} | {utilization}% | {memory_used_GB:.1f}GB ({memory_percentage:.0f}%) | {users_str} |"
            rows.append(row)

        return '\n'.join(rows), is_any_free

    def should_call_function_during_chinese_workdays(self, server_ip):
        """
        检查是否为中国工作日以及指定时间段。
        """
        now = datetime.now()
        current_time = now.time()

        if not calendar.is_workday(now):
            return False

        in_any_time_range = False
        for time_range in self.time_range:
            start_time = datetime.strptime(time_range[0], '%H:%M').time()
            end_time = datetime.strptime(time_range[1], '%H:%M').time()
            if start_time <= end_time:
                in_time_range = start_time <= current_time <= end_time
            else:
                in_time_range = start_time <= current_time or current_time <= end_time
            if in_time_range:
                in_any_time_range = True
                break

        if in_any_time_range:
            last_time = self.last_true_time.get(server_ip)
            if last_time is None or (now - last_time).total_seconds() >= self.time_interval * 60:
                self.last_true_time[server_ip] = now
                return True

        return False

# 实例化类
messager = Messenger(token="",
                     secret="")
