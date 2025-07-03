import time
import requests
import json
import datetime
import threading
import random, re
import os
import io
import sys
import base64
import gzip
import hashlib
import random
import pyDes  
from py3rijndael import RijndaelCbc, ZeroPadding
from collections import OrderedDict
import colorama
from colorama import Fore, Back, Style
colorama.init()
PACKET_DELAY = 0.05
username="114514IMIKUN54188坤坤"  #请将得到的账号填入这里
send_多线程延迟 = 0.35  # 设置多线程延迟, 建议0.2, 最低0.17
无尽延迟 = 0.05 # 设置无尽每次多线程延迟, 建议0.05至0.1之间，网络越好填越低
id_庭院 = 0  # 填写庭院关卡号
i_0 = 0  # 输入的自动庭院执行次数
count_庭院 = 0  # 自动庭院计数
count_联赛 = 0  # 自动联赛计数
count_材料 = 0
latency = 0  # 初始化加解密延迟
latency_拓维 = 0  # 初始化游戏服务器延迟
c_庭院关卡号 = []  # 查询的庭院关卡号
count_追击币 = 0  # 初始化追击币计数
newest_version = "3.7.4"
newest_version_code = 1530
渠道 = "com.popcap.pvz2cthdbk"
tw_url='https://pvz2.ditwan.cn/backend/api/latest_version/get_latest_version'
pi, sk, ui, uk = "", "", "", ""

# 填入抓取的数据包用来获取sk.ui.pi
def load_data_config():
    """从相同目录下的 data_config.txt 文件读取数据包配置"""
    try:        # 获取脚本所在目录
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(script_dir, "data_config.txt")
        # 读取配置文件
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content:
                return content
            else:
                print("data_config.txt 文件为空")
                return ""
    except FileNotFoundError:
        print("未找到 data_config.txt 配置文件，将创建空文件")
        # 创建空的配置文件
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(script_dir, "data_config.txt")
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write("")
            print(f"已创建空的配置文件: {config_file}")
        except Exception as e:
            print(f"创建配置文件失败: {e}")
        return ""
    except Exception as e:
        print(f"读取配置文件出错: {e}")
        return ""

# 填入抓取的数据包用来获取sk.ui.pi
data_0 = load_data_config()

# ===== DES 加解密功能 =====
def md5(text: str) -> str:
    """MD5哈希函数"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def des_encrypt(data: str) -> str:
    """DES加密"""
    key = b"TwPay001"
    iv = bytes([1,2,3,4,5,6,7,8])
    k = pyDes.des(key, pyDes.CBC, iv, padmode=pyDes.PAD_PKCS5)
    return k.encrypt(data.encode("utf-8")).hex().upper()

def des_decrypt(data_hex: str) -> str:
    """DES解密"""
    key = b"TwPay001"
    iv = bytes([1,2,3,4,5,6,7,8])
    k = pyDes.des(key, pyDes.CBC, iv, padmode=pyDes.PAD_PKCS5)
    return k.decrypt(bytes.fromhex(data_hex)).decode("utf-8")

# ===== 账号密码管理功能 =====
def load_account_config():
    """从相同目录下的账号密码.txt文件读取账号密码配置"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(script_dir, "账号密码.txt")
        
        with open(config_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) >= 2:
                account = lines[0].strip()
                password = lines[1].strip()
                return account, password
            else:
                print("账号密码文件格式错误，需要两行，第一行账号，第二行密码")
                return None, None
    except FileNotFoundError:
        print("未找到账号密码.txt文件，将创建新文件")
        return create_account_config()

def create_account_config():
    """创建账号密码配置文件"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, "账号密码.txt")
    
    print("请输入账号密码信息：")
    account = input("账号: ").strip()
    password = input("密码: ").strip()
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(f"{account}\n{password}\n")
        print(f"账号密码已保存到 {config_file}")
        return account, password
    except Exception as e:
        print(f"保存账号密码失败: {e}")
        return None, None

def load_token_cache():
    """加载token缓存"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        token_file = os.path.join(script_dir, "token_cache.json")
        
        with open(token_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_token_cache(token_cache):
    """保存token缓存，现在包含token和user_id"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        token_file = os.path.join(script_dir, "token_cache.json")
        
        with open(token_file, 'w', encoding='utf-8') as f:
            json.dump(token_cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存token缓存失败: {e}")

def login_with_account_password(account: str, password: str, last_token: str = ""):
    """使用账号密码登录 - 完全按照AESandDES.py的方式"""
    appkey = "b0b29851-b8a1-4df5-abcb-a8ea158bea20"
    head_plain = json.dumps({
        "appId": 109,
        "channelId": 208,
        "sdkVersion": "2.0.0"
    }, separators=(',', ':'))

    login_dict = {
        "password": md5(password),
        "phone": account
    }
    if last_token:
        login_dict["token"] = last_token

    login_plain = json.dumps(login_dict, separators=(',', ':'))

    head_enc = des_encrypt(head_plain)
    login_enc = des_encrypt(login_plain)
    md5_val = hashlib.md5((login_plain + appkey).encode('utf-8')).hexdigest()

    url = "http://tgpay.talkyun.com.cn/tw-sdk/sdk-api/user/login"
    data = {
        "head": head_enc,
        "login": login_enc,
        "md5": md5_val
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; 22021211RC Build/TKQ1.220807.001)"
    }
    resp = requests.post(url, data=data, headers=headers)
    if resp.status_code == 200:
        first = des_decrypt(resp.text.strip())
        content_hex = json.loads(first)["content"]
        second = des_decrypt(content_hex)
        user_info = json.loads(second)
        token = user_info["token"].strip()
        user_id = str(user_info["userId"])
        print("登录成功")
        print("token:", token)
        return True, token, user_id
    else:
        print("登录失败")
        response_hex = resp.text.strip()
        try:
            first_layer = des_decrypt(response_hex)
            parsed = json.loads(first_layer)
            print("第一层解密结果：", parsed)
        except Exception as e:
            print("第一层解密失败：", response_hex)
            return False, None, None
        content_hex = parsed.get("content")
        if not content_hex:
            print("content字段不存在，第一层解密结果：", parsed)
        else:
            try:
                second_layer = des_decrypt(content_hex)
                print("第二层解密结果：", second_layer)
            except Exception as e:
                print("第二层解密失败，第一层解密结果：", parsed)
        return False, None, None

def build_v202_packet(account: str, token: str, user_id: str = "") -> dict:
    """构建V202数据包"""
    s_value = "61984bc24786cddf91e1cc735901e6b7"
    e_plain = {
        "ci": "93",
        "cv": f"{newest_version}.1645",  # 使用变量确保版本一致性
        "di": "",
        "head": {
            "appId": "109",
            "appVersion": "1.0",
            "channelId": "208",
            "channelSdkVersion": "dj2.0-2.0.0",
            "talkwebSdkVersion": "3.0.0"
        },
        "li": "5dc566d17e52f72d7df753e9dee4ccc2",
        "oi": f"109208X{account}",
        "pi": "",
        "r": "203855139",
        "s": s_value,
        "t": token,
        "ui": ""  # 使用传入的user_id
    }
    return {
        "req": "V202",
        "e": e_plain,
        "ev": 1
    }

def build_form_data_for_login(identifier: str, e_plain, ev: str = "1") -> str:
    """为登录构建form数据 - 修复版本，参考talkweb_handler"""
    if not isinstance(e_plain, dict):
        raise TypeError("e_plain must be a dictionary")
    
    # 使用正确的加密方法 - 直接传入字典而不是字符串
    try:
        # 这里改用正确的加密方式
        plain_bytes = json.dumps(e_plain, separators=(',', ':')).encode('utf-8')
        key = get_key(identifier)
        iv = get_iv(identifier)
        block_size = 24
        
        # 使用ZeroPadding而不是手动padding
        cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(block_size), block_size=block_size)
        encrypted_bytes = cipher.encrypt(plain_bytes)
        encrypted_e = base64_url_encode(encrypted_bytes)
        
    except Exception as e:
        print(f"V202加密失败: {e}")
        raise
    
    boundary = "_{{}}_"
    return (
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="req"\r\n\r\n'
        f'{identifier}\r\n'
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="e"\r\n\r\n'
        f'{encrypted_e}\r\n'
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="ev"\r\n\r\n'
        f'{ev}\r\n'
        f'--{boundary}--'
    )

def get_ui_sk_from_account(account: str, token: str, user_id: str = ""):
    """通过账号和token获取ui、sk - 完全按照AESandDES.py的方式"""
    identifier = "V202"
    s_value = "b674150ac53b131892d80d1e9f234fd0"  # 固定写死，和AESandDES.py一致
    e_plain = {
        "ci": "93",
        "cv": "3.7.3.1645",
        "di": "",
        "head": {
            "appId": "109",
            "appVersion": "1.0",
            "channelId": "208",
            "channelSdkVersion": "dj2.0-2.0.0",
            "talkwebSdkVersion": "3.0.0"
        },
        "li": "5dc566d17e52f72d7df753e9dee4ccc2",
        "oi": f"109208X{account}",
        "pi": "",
        "r": "776988319",
        "s": s_value,
        "t": token,
        "ui": ""
    }
    
    # 使用和AESandDES.py相同的加密方式
    plain_bytes = json.dumps(e_plain, separators=(',', ':')).encode('utf-8')
    key = get_key(identifier)
    iv = get_iv(identifier)
    cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(24), block_size=24)
    padded = plain_bytes + b'\x00' * ((24 - len(plain_bytes) % 24) % 24)
    encrypted = cipher.encrypt(padded)
    e_enc = base64_url_encode(encrypted)
    
    # 构建form_data，和AESandDES.py完全一致
    boundary = "_{{}}_"
    form_data = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="req"\r\n\r\n'
        f"{identifier}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="e"\r\n\r\n'
        f"{e_enc}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="ev"\r\n\r\n'
        f"1\r\n"
        f"--{boundary}--"
    )
    
    url = "http://cloudpvz2android.ditwan.cn/index.php"
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; 22021211RC Build/TKQ1.220807.001)"
    }
    
    try:
        resp = requests.post(url, data=form_data.encode('utf-8'), headers=headers)
        print(f"获取请求状态码: {resp.status_code}")
        
        if resp.status_code == 200:
            try:
                resp_json = resp.json()
                identifier2 = resp_json.get("i")
                encrypted_e = resp_json.get("e")
                if identifier2 and encrypted_e:
                    key = get_key(identifier2)
                    iv = get_iv(identifier2)
                    raw = base64_url_decode(encrypted_e)
                    cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(24), block_size=24)
                    decrypted = cipher.decrypt(raw)
                    decrypted_str = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
                    
                    d_json = json.loads(decrypted_str)
                    d = d_json.get("d", {})
                    ui = d.get("ui")
                    sk = d.get("sk")
                    pi = d.get("pi", "")
                    uk = d.get("uk", "")
                    
                    print("ui:", ui)
                    print("sk:", sk)
                    return True, ui, sk, pi, uk
                else:
                    print("获取ui/sk失败")
            except Exception as e:
                print(f"解析响应失败: {e}")
                try:
           
                   key = get_key(identifier2)
                   iv = get_iv(identifier2)
                   raw = base64_url_decode(encrypted_e)
                   cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(24), block_size=24)
                   decrypted = cipher.decrypt(raw)
                   decrypted_str = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
                   print("解密后的响应内容:", decrypted_str)
                except Exception as ex:
                    print("解密响应失败:", ex)
        else:
            print("获取ui/sk失败")
    except Exception as e:
        print(f"获取ui/sk请求失败: {e}")
    
    return False, None, None, None, None

def save_data_config(encrypted_data):
    """保存加密的数据包到配置文件"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(script_dir, "data_config.txt")
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
        return True
    except Exception as e:
        print(f"保存配置文件失败: {e}")
        return False

def build_v210_packet_and_save(ui, sk):
    """构建V210数据包并保存到配置文件"""
    try:
        # 构建V210数据包
        v210_data = {
            "req": "V210",
            "e": {
                "ci": "-1",
                "pi": ui,  # pi和ui值相同
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        
        # 使用CNNetwork加密
        encrypted_data = CNNetwork.encrypt(json.dumps(v210_data, separators=(',', ':')))
        
        if encrypted_data:
            # 保存到配置文件
            if save_data_config(encrypted_data):
                return True
            else:
                print("保存V210数据包失败")
                return False
        else:
            print("加密V210数据包失败")
            return False
    except Exception as e:
        print(f"构建V210数据包失败: {e}")
        return False

def prompt_user_paste_package():
    """提示用户粘贴数据包"""
    print("\n" + "="*50)
    print("请粘贴新的数据包 (粘贴完成后输入'0'保存，直接回车跳过):")
    
    lines = []
    while True:
        line = input()
        if line.strip() == "0":
            if lines:
                # 用户输入了数据包，保存到文件
                package_data = "\n".join(lines)
                if save_data_config(package_data):
                    print("数据包已保存")
                    return True
                else:
                    print("保存数据包失败")
                    return False
            else:
                print("没有输入任何数据包内容")
                return False
        elif line.strip() == "":
            if not lines:
                # 直接回车，跳过
                print("跳过数据包更新")
                return False
            else:
                # 添加空行到数据包
                lines.append(line)
        else:
            lines.append(line)

def auto_login_and_get_ui_sk():
    """自动登录并获取ui、sk"""
    global pi, sk, ui, uk, data_0
      # 加载账号密码
    account, password = load_account_config()
    if not account or not password:
        print("无法获取账号密码，跳过自动登录")
        return False
    
    # 加载token缓存
    token_cache = load_token_cache()
    cached_info = token_cache.get(account, {})
    cached_token = cached_info.get("token") if isinstance(cached_info, dict) else cached_info
    cached_user_id = cached_info.get("user_id", "") if isinstance(cached_info, dict) else ""
    
    # 尝试使用缓存的token直接获取ui、sk
    if cached_token:
        success, ui_val, sk_val, pi_val, uk_val = get_ui_sk_from_account(account, cached_token, cached_user_id)
        if success:
            print("使用缓存token成功获取ui、sk")
            pi, sk, ui, uk = pi_val, sk_val, ui_val, uk_val
            # 构建并保存V210数据包
            if build_v210_packet_and_save(ui, sk):
                # 重新加载配置文件
                data_0 = load_data_config()
            return True
        else:
            print("缓存token已过期，需要重新登录")
      # token无效或不存在，执行登录
    print(f"正在登录账号: {account}")
    print(f"使用token: {cached_token if cached_token else '无'}")
    
    success, token, user_id = login_with_account_password(account, password, cached_token)
    
    if success:
        print(f"登录成功")
        print(f"获得新token: {token}")
        token_cache[account] = {
            "token": token,
            "user_id": user_id
        }
        save_token_cache(token_cache)
        
        # 获取ui、sk - 这里传入正确的user_id
        print("正在获取ui、sk")
        success2, ui_val, sk_val, pi_val, uk_val = get_ui_sk_from_account(account, token, user_id)
        if success2:
            pi, sk, ui, uk = pi_val, sk_val, ui_val, uk_val
            # 构建并保存V210数据包
            if build_v210_packet_and_save(ui, sk):
                # 重新加载配置文件
                data_0 = load_data_config()
            return True
        else:
            print("获取ui、sk失败")
    else:
        print("登录失败")
    
    return False

def check_package_expiry_and_login():
    """检查数据包是否过期，如果过期提示用户选择登录方式"""
    global pi, sk, ui, uk, data_0
    
    try:
        # 尝试解析当前数据包
        if data_0.strip():  # 只有在数据包不为空时才尝试解析
            decrypted_data = CNNetwork.decrypt(data_0)
            res = json.loads(decrypted_data)
            
            # 检查是否包含有效的数据
            if "e" in res and "d" in res["e"]:
                d = res["e"]["d"]
                current_ui = d.get("ui", "")
                current_sk = d.get("sk", "")
                current_pi = d.get("pi", "")
                current_uk = d.get("uk", "")
                
                if current_ui and current_sk:
                    print("当前数据包有效，使用现有配置")
                    pi, sk, ui, uk = current_pi, current_sk, current_ui, current_uk
                    return True
        else:
            print("数据包配置文件为空")
    
    except Exception as e:
        print(f"数据包解析失败: {e}")
    
    # 数据包无效或为空，提供选项
    print("\n检测到数据包可能已过期、无效或为空")
    print("请选择操作:")
    print("1. 通过账号密码登录获取新的ui、sk")
    print("2. 粘贴新的数据包")
    print("直接回车跳过")
    
    choice = input("请输入选择: ").strip()
    
    if choice == "1":
        if auto_login_and_get_ui_sk():
            return True
        else:
            print("账号密码登录失败，请检查账号密码或网络连接")
    elif choice == "2":
        if prompt_user_paste_package():
            print("数据包已更新，重新加载配置...")
            # 重新加载配置文件
            data_0 = load_data_config()
            return check_package_expiry_and_login()  # 递归验证新数据包
        else:
            print("未更新数据包")
    else:
        print("跳过数据包更新，继续使用原配置")
    
    return False

KEY_CACHE = {}
IV_CACHE = {}
BOUNDARY_REGEX = re.compile(r'^(--[^\n]+)', re.MULTILINE)
NAME_REGEX = re.compile(r'name\s*=\s*["\']?([^"\'\s;]+)["\']?', re.IGNORECASE)

def base64_url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').replace('=', ',')

def base64_url_decode(data: str) -> bytes:
    data = data.strip().replace('\n', '').replace('\r', '').replace(' ', '').replace(',', '=')
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data.encode('utf-8'))

def get_key(identifier: str) -> bytes:
    if identifier not in KEY_CACHE:
        s = f"`jou*{identifier})xoj'"
        md5 = hashlib.md5(s.encode('utf-8')).hexdigest()
        KEY_CACHE[identifier] = md5.encode('utf-8')
    return KEY_CACHE[identifier]

def get_iv(identifier: str) -> bytes:
    if identifier not in IV_CACHE:
        key_str = get_key(identifier).decode('utf-8')
        digits = ''.join([c for c in identifier if c.isdigit()])
        pos = int(digits) if digits else 0
        start = pos % 7
        end = start + 24
        iv_bytes = key_str[start:end].encode('utf-8')
        if len(iv_bytes) < 24:
            iv_bytes += key_str[:24 - len(iv_bytes)].encode('utf-8')
        IV_CACHE[identifier] = iv_bytes
    return IV_CACHE[identifier]

def zero_pad(data: bytes, block_size: int) -> bytes:
    pad_len = (block_size - len(data) % block_size) % block_size
    return data + b'\x00' * pad_len

def encrypt_twnetwork(identifier: str, plain: str) -> str:
    key = get_key(identifier)
    iv = get_iv(identifier)
    block_size = 24
    plain_bytes = plain.encode('utf-8')
    padded = zero_pad(plain_bytes, block_size)
    cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(block_size), block_size=block_size)
    encrypted = cipher.encrypt(padded)
    return base64_url_encode(encrypted)

def decrypt_twnetwork(identifier: str, encrypted: str) -> str:
    encrypted_clean = encrypted.strip().replace('\n', '').replace('\r', '').replace(' ', '')
    if not encrypted_clean:
        return ""
    key = get_key(identifier)
    iv = get_iv(identifier)
    block_size = 24
    try:
        raw = base64_url_decode(encrypted_clean)
        if len(raw) == 0 or len(raw) % block_size != 0:
            raise ValueError(f"Invalid ciphertext length for {identifier}")
        cipher = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(block_size), block_size=block_size)
        decrypted = cipher.decrypt(raw)
        return decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
    except Exception as e:
        raise ValueError(f"Decryption failed for {identifier}: {e}")

def parse_form_data(data_str: str) -> dict:
    data_str = data_str.replace('\r\n', '\n').replace('\r', '\n')
    boundary_match = BOUNDARY_REGEX.search(data_str)
    if not boundary_match:
        raise ValueError("Cannot determine boundary from form data")
    boundary = boundary_match.group(1)
    parts = data_str.split(boundary)
    result = {}
    for part in parts:
        part = part.strip()
        if not part or part.startswith('--'):
            continue
        sections = re.split(r'\n\n', part, maxsplit=1)
        if len(sections) != 2:
            continue
        headers, value = sections
        name_match = NAME_REGEX.search(headers)
        if name_match:
            result[name_match.group(1)] = value.strip("\n")
    if not result:
        raise ValueError("Failed to parse form data")
    return result

def local_decrypt_general_input(data_str: str):
    """本地解密通用输入"""
    fields = {}
    if "Content-Disposition" in data_str and "--" in data_str:
        try:
            fields = parse_form_data(data_str)
        except ValueError:
            pass
    
    if fields and "req" in fields and "e" in fields:
        identifier = fields["req"]
        encrypted_e = fields["e"]
        ev_val = fields.get("ev", "1")
    else:
        try:
            parsed_json = json.loads(data_str)
            if "req" in parsed_json and "e" in parsed_json and isinstance(parsed_json["e"], str):
                identifier = parsed_json["req"]
                encrypted_e = parsed_json["e"]
                ev_val = str(parsed_json.get("ev", "1"))
            else:
                raise ValueError("Invalid JSON format")
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON decode error: {e}")
    
    decrypted_e_str = decrypt_twnetwork(identifier, encrypted_e)
    try:
        e_content = json.loads(decrypted_e_str)
    except json.JSONDecodeError:
        e_content = decrypted_e_str
    
    return OrderedDict([
        ("req", identifier),
        ("e", e_content),
        ("ev", int(ev_val) if isinstance(ev_val, str) and ev_val.isdigit() else ev_val)
    ])

def local_build_encrypted_form_data_as_output(identifier: str, e_plain_content: dict, ev_val: str = "1") -> str:
    boundary = "_{{}}_"
    if not isinstance(e_plain_content, dict):
        raise TypeError("e_plain_content must be a dictionary")
    e_plain_str = json.dumps(e_plain_content, separators=(',', ':'), ensure_ascii=False)
    encrypted_e = encrypt_twnetwork(identifier, e_plain_str)
    
    parts = [
        f'--{boundary}\nContent-Disposition: form-data; name="req"\n\n{identifier}\n',
        f'--{boundary}\nContent-Disposition: form-data; name="e"\n\n{encrypted_e}\n',
        f'--{boundary}\nContent-Disposition: form-data; name="ev"\n\n{ev_val}\n',
        f'--{boundary}--\n'
    ]
    return "".join(parts)

def local_decrypt_encrypted_json_response_input(resp_json_str: str):
    """本地解密JSON响应输入"""
    try:
        resp = json.loads(resp_json_str)
        identifier = resp.get("i")
        encrypted_e = resp.get("e")
        ev_val = resp.get("ev", 1)
        if not identifier or not isinstance(encrypted_e, str):
            return resp
        decrypted_e_str = decrypt_twnetwork(identifier, encrypted_e)
        try:
            e_content = json.loads(decrypted_e_str)
        except json.JSONDecodeError:
            e_content = decrypted_e_str
        
        return OrderedDict([
            ("i", identifier),
            ("r", resp.get("r", 0)),
            ("e", e_content),
            ("ev", int(ev_val) if isinstance(ev_val, str) and str(ev_val).isdigit() else ev_val)
        ])
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON response format")

def local_encrypt_json_response_payload_output(input_json_dict: dict) -> dict:
    identifier = input_json_dict.get("i")
    e_payload_dict = input_json_dict.get("e")
    ev_val = input_json_dict.get("ev", 1)
    if not identifier or not isinstance(e_payload_dict, dict):
        raise ValueError("Invalid input format for encryption")
    e_payload_str = json.dumps(e_payload_dict, separators=(',', ':'), ensure_ascii=False)
    encrypted_e_str = encrypt_twnetwork(identifier, e_payload_str)
    return {
        "i": identifier,
        "e": encrypted_e_str,
        "ev": int(ev_val) if isinstance(ev_val, str) and str(ev_val).isdigit() else ev_val
    }

class CNNetwork:
    """本地加解密网络类 - 不再依赖外部API"""
    
    def __init__(self):
        # 初始化延迟统计
        global latency
        latency = 0

    @staticmethod
    def _time_operation(func, *args, **kwargs):
        """统计操作耗时"""
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            end_time = time.time()
            global latency
            latency = (end_time - start_time) * 1000  # 转换为毫秒
            return result
        except Exception as e:
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            raise e

    @classmethod
    def encrypt(cls, plain: str):
        """加密字符串 - 新格式兼容"""
        try:
            # 这里需要根据实际使用场景来判断加密格式
            # 默认假设是请求格式的加密
            def _encrypt():
                # 如果是JSON格式，尝试解析
                try:
                    data = json.loads(plain)
                    if "req" in data and "e" in data:
                        # 请求格式加密
                        identifier = data["req"]
                        e_content = data["e"]
                        ev_val = str(data.get("ev", "1"))
                        return local_build_encrypted_form_data_as_output(identifier, e_content, ev_val)
                    elif "i" in data and "e" in data:
                        # 响应格式加密
                        return json.dumps(local_encrypt_json_response_payload_output(data), ensure_ascii=False)
                    else:
                        raise ValueError("Unknown JSON format for encryption")
                except json.JSONDecodeError:
                    # 如果不是JSON，直接返回原文本（可能需要根据具体情况调整）
                    return plain
            
            return cls._time_operation(_encrypt)
        except Exception as e:
            print(f"本地加密失败: {e}")
            return None

    @classmethod
    def encrypt_dict(cls, plain_dict):
        """加密字典"""
        try:
            def _encrypt():
                if "req" in plain_dict and "e" in plain_dict:
                    # 请求格式
                    identifier = plain_dict["req"]
                    e_content = plain_dict["e"]
                    ev_val = str(plain_dict.get("ev", "1"))
                    return local_build_encrypted_form_data_as_output(identifier, e_content, ev_val)
                elif "i" in plain_dict and "e" in plain_dict:
                    # 响应格式
                    encrypted = local_encrypt_json_response_payload_output(plain_dict)
                    return json.dumps(encrypted, ensure_ascii=False)
                else:
                    raise ValueError("Unknown dict format for encryption")
            
            return cls._time_operation(_encrypt)
        except Exception as e:
            print(f"本地字典加密失败: {e}")
            print("原始数据：", plain_dict)
        return json.dumps(plain_dict, ensure_ascii=False)
    @classmethod
    def decrypt(cls, cipher: str):
        """解密字符串"""
        try:
            def _decrypt():
                # 尝试不同的解密格式
                try:
                    # 尝试JSON响应格式
                    parsed = json.loads(cipher)
                    if "i" in parsed and "e" in parsed and isinstance(parsed["e"], str):
                        # JSON响应格式解密
                        decrypted = local_decrypt_encrypted_json_response_input(cipher)
                        return json.dumps(decrypted, ensure_ascii=False)
                    else:
                        # 其他JSON格式，尝试通用解密
                        decrypted = local_decrypt_general_input(cipher)
                        return json.dumps(decrypted, ensure_ascii=False)
                except json.JSONDecodeError:
                    # 不是JSON，可能是form-data格式
                    if "Content-Disposition" in cipher and "--" in cipher:
                        # form-data格式解密
                        decrypted = local_decrypt_general_input(cipher)
                        return json.dumps(decrypted, ensure_ascii=False)
                    else:
                        # 其他格式，直接返回
                        return cipher
            
            return cls._time_operation(_decrypt)
        except Exception as e:
            print("本地解密失败:")
            return cipher

    @classmethod
    def make_获取小号(cls):
        """获取小号 - 本地模式不再需要网络请求"""
        # 这个功能可能需要根据实际需求来实现
        # 这里返回一个默认值或者抛出异常
        print("本地模式下不支持获取小号功能")
        return None
        
植物字典 = {
    "1001": "豌豆射手",
    "1002": "向日葵",
    "1003": "坚果",
    "1004": "土豆地雷",
    "1005": "卷心菜投手",
    "1006": "冰冻生菜",
    "1007": "回旋镖射手",
    "1008": "双胞向日葵",
    "1009": "菜问",
    "1010": "弹簧豆",
    "1011": "地刺",
    "1012": "火龙草",
    "1013": "能量花",
    "1014": "窝瓜",
    "1015": "巴豆",
    "1016": "双向射手",
    "1017": "火爆辣椒",
    "1018": "噬碑藤",
    "1019": "寒冰豌豆",
    "1020": "火炬树桩",
    "1021": "玉米投手",
    "1022": "闪电芦苇",
    "1023": "椰子加农炮",
    "1024": "西瓜投手",
    "1025": "豌豆荚",
    "1026": "变身茄子",
    "1027": "双重射手",
    "1028": "钢地刺",
    "1029": "高坚果",
    "1030": "三重射手",
    "1031": "冰西瓜投手",
    "1032": "樱桃炸弹",
    "1033": "仙桃",
    "1034": "火葫芦",
    "1035": "白萝卜",
    "1036": "竹笋",
    "1037": "棱镜草",
    "1039": "激光豆",
    "1040": "星星果",
    "1041": "三叶草",
    "1042": "脉冲黄桃",
    "1043": "充能柚子",
    "1044": "全息坚果",
    "1045": "瓷砖萝卜",
    "1047": "胡萝卜导弹车",
    "1049": "小喷菇",
    "1050": "大喷菇",
    "1051": "魅惑菇",
    "1052": "阳光菇",
    "1053": "阳光豆",
    "1054": "花生射手",
    "1055": "磁力菇",
    "1056": "路灯花",
    "1057": "咖啡豆",
    "1058": "寒冰菇",
    "1059": "烈焰菇",
    "1060": "橡木弓手",
    "1061": "蒲公英",
    "1062": "大力花菜",
    "1063": "机枪石榴",
    "1064": "莲叶",
    "1065": "保龄泡泡",
    "1066": "缠绕水草",
    "1067": "香蕉火箭炮",
    "1068": "鳄梨",
    "1069": "导向蓟",
    "1070": "大嘴花",
    "1071": "强酸柠檬",
    "1072": "幽灵辣椒",
    "1073": "甜薯",
    "1074": "竹员外",
    "1075": "莲小蓬",
    "1076": "树脂投手",
    "1077": "飓风甘蓝",
    "1078": "火焰豌豆射手",
    "1079": "烤马铃薯",
    "1080": "辣椒投手",
    "1081": "甜菜护卫",
    "1082": "眩晕洋葱",
    "1083": "旋转芜菁",
    "1084": "大王花",
    "1085": "旋风橡果",
    "1086": "板栗小队",
    "1088": "竹小弟",
    "1089": "漩涡枇杷",
    "1090": "电离红掌",
    "1091": "芦笋战机",
    "1092": "飞碟瓜",
    "1093": "蚕豆突击队",
    "1094": "灯笼草",
    "1095": "旋转菠萝",
    "1097": "魔术菇",
    "1098": "玫瑰剑客",
    "1099": "电击蓝莓",
    "111001": "捣蛋萝卜",
    "111002": "向日葵歌手",
    "111003": "榴莲",
    "111004": "南瓜巫师",
    "111006": "黄金叶",
    "111008": "阿开木木",
    "111009": "红针花",
    "111010": "大丽菊",
    "111011": "岩浆番石榴",
    "111012": "金蟾菇",
    "111013": "棉小雪",
    "111014": "菠萝蜜",
    "111015": "龙舌兰",
    "111016": "猕猴桃",
    "111017": "梅小美",
    "111018": "火龙果",
    "111019": "天使星星果",
    "111020": "火柴花拳手",
    "111021": "火焰花女王",
    "111022": "机枪射手",
    "111023": "魔音甜菜",
    "111024": "逆时草",
    "111025": "潜伏芹菜",
    "111026": "孢子菇",
    "111027": "大蒜",
    "111028": "复活萝卜",
    "111029": "仙人掌",
    "111030": "猫尾草",
    "111031": "喇叭花",
    "111032": "爆裂葡萄",
    "111033": "冰龙草",
    "111034": "缩小紫罗兰",
    "111035": "原始豌豆射手",
    "111036": "原始坚果",
    "111037": "香水蘑菇",
    "111038": "原始向日葵",
    "111039": "原始土豆地雷",
    "111040": "龙吼草",
    "111041": "胆小荆棘",
    "111042": "原始大王花",
    "111043": "蔗师傅",
    "111044": "玉米加农炮",
    "111045": "苹果迫击炮",
    "111046": "金缕梅女巫",
    "111047": "逃脱树根",
    "111048": "电流醋栗",
    "111049": "白瓜相扑手",
    "111050": "超能花菜",
    "111051": "毒影菇",
    "111052": "月光花",
    "111053": "爆炸坚果",
    "111054": "夜影龙葵",
    "111055": "幽暮投手",
    "111056": "铃儿草投手",
    "111058": "暗樱草",
    "111060": "炙热山葵",
    "111061": "防风草",
    "111062": "槲寄冰仙子",
    "111063": "野兽猕猴桃",
    "111064": "黄金蓓蕾",
    "111065": "平顶菇",
    "111066": "莲藕射手",
    "111067": "芦黎药师",
    "111068": "番莲工程师",
    "111069": "吹风荚兰",
    "111070": "桑葚爆破手",
    "111071": "电能豌豆",
    "111072": "寒冰醋栗",
    "111073": "热辣海枣",
    "111074": "郁金香号手",
    "111075": "茄子忍者",
    "111076": "芭蕉舞蹈家",
    "111078": "水仙花射手",
    "111079": "双枪松果",
    "111081": "警爆磁菇",
    "111082": "冬青骑士",
    "111084": "暗影豌豆",
    "111085": "食人花豌豆",
    "111086": "水晶兰",
    "111087": "豌豆迫击炮",
    "111088": "雷龙草",
    "111089": "芦荟医师",
    "111090": "熊果臼炮",
    "111091": "冬瓜守卫",
    "200000": "电力绿茶",
    "200001": "小黄梨",
    "200002": "宝石商石榴",
    "200003": "油橄榄",
    "200004": "白露花战机",
    "200005": "爆炸草莓",
    "200006": "毒液豌豆射手",
    "200007": "杜英投手",
    "200008": "飞镖洋蓟",
    "200009": "荸荠兄弟",
    "200010": "尖刺秋葵",
    "200011": "铜钱草鼓手",
    "200012": "终极番茄",
    "200013": "潜行开口箭",
    "200014": "暗影荚兰",
    "200015": "凤梨链刃",
    "200016": "千金藤",
    "200017": "滴水冰莲",
    "200018": "石斛防风网",
    "200019": "厨师杓兰",
    "200020": "粘液桉果",
    "200021": "橄榄坑",
    "200022": "刺眼花艺伎",
    "200023": "黏弹糯米",
    "200024": "地星发射井",
    "200025": "奶油生菜",
    "200026": "眩晕雏菊",
    "200027": "爆炸桔梗",
    "200028": "庆典汽水椰",
    "200029": "钩爪嘉兰",
    "200030": "花盆",
    "200031": "凤仙花射手",
    "200032": "火鸡投手",
    "200033": "铁锤兰",
    "200034": "聚能山竹",
    "200035": "鱼钩草",
    "200037": "烈焰火蕨",
    "200038": "虎头菇",
    "200039": "气流水仙花",
    "200041": "地锯草",
    "200043": "石楠探索者",
    "200044": "树灵护卫",
    "200045": "疯帽菇",
    "200046": "魔法番红花",
    "200047": "公主弹簧草",
    "200048": "突击竹兵",
    "200049": "刺果流星锤",
    "200050": "黄油毛艮",
    "200051": "激光皇冠花",
    "200052": "腐尸豆荚",
    "200053": "扇贝兰法师",
    "200054": "杰克南瓜灯",
    "200055": "豌豆药剂师",
    "200056": "双生卯兔",
    "200057": "长枪球兰",
    "200058": "牛蒡击球手",
    "200059": "吸血牛杆菌",
    "200060": "南瓜头",
    "200061": "鹳草击剑手",
    "200062": "蓄电雪松果",
    "200063": "电能藤蔓",
    "200064": "蛇妖瓶子草",
    "200065": "流星花",
    "200066": "曼德拉草",
    "200067": "深渊海葵",
    "200068": "深渊魔爪花",
    "200069": "粉丝心叶兰",
    "200070": "豌豆藤蔓",
    "200071": "蜜蜂铃兰",
    "200072": "油菜花",
    "200073": "剑叶龙血树",
    "200074": "斯巴达竹",
    "200075": "闪耀藤蔓",
    "200076": "阳光韭菜",
    "200077": "暗夜菇",
    "200078": "柴堆藤蔓",
    "200079": "贪吃龙草",
    "200080": "兔极",
    "200081": "植甲拼装者-炎星",
    "200082": "蝎尾蕉机枪手",
    "200083": "电鳗香蕉",
    "200084": "荆棘巫师",
    "200085": "锯齿锦地罗",
    "200086": "寄生仙钗",
    "200088": "暴君火龙果",
    "200089": "小暴君火龙果",
    "200090": "忧郁藤蔓",
    "200091": "电击鹰爪花",
    "200092": "留声曼陀罗",
    "200093": "疯狂炮仗花",
    "200094": "日月金银花",
    "200095": "蛮族大黄",
    "200096": "水生藤蔓",
    "200097": "寒霜白毛丹",
    "200098": "电击钩吻",
    "200099": "寒冰地刺",
    "200100": "珊瑚泡泡姬",
    "200101": "百宝兜兰",
    "200102": "女娲蛇尾草",
    "200126": "爆浆玉露",
    "200127": "枫影刺客",
    "200128": "守卫菇",}

植物碎片字典 = {
            # 白色品质
                "1101": "豌豆射手碎片", "1102": "向日葵碎片", "1103": "坚果碎片", "1104": "土豆地雷碎片",
                "1105": "卷心菜投手碎片", "1106": "冰冻生菜碎片", "1110": "弹簧豆碎片", "1111": "地刺碎片",
                "1115": "巴豆碎片", "1118": "噬碑藤碎片", "1121": "玉米投手碎片", "1133": "仙桃碎片",
                "1134": "火葫芦碎片", "1135": "白萝卜碎片", "1136": "竹笋碎片", "1149": "小喷菇碎片",
                "1150": "大喷菇碎片", "1153": "阳光豆碎片", "1154": "花生射手碎片", "1155": "磁力菇碎片",
                "1156": "路灯花碎片", "1157": "咖啡豆碎片", "1164": "莲叶碎片", "1166": "缠绕水草碎片",
                "1179": "烤马铃薯碎片", "1194": "灯笼草碎片", "111106": "黄金叶碎片", "111110": "大丽菊碎片",
                "111141": "胆小荆棘碎片", "111164": "黄金蓓蕾碎片", "111165": "平顶菇碎片",
                "22000170": "滴水冰莲碎片", "22000300": "花盆碎片",
                # 绿色品质
                "1107": "回旋镖射手碎片", "1116": "双向射手碎片", "1119": "寒冰豌豆碎片",
                "1120": "火炬树桩碎片", "1122": "闪电芦苇碎片", "1124": "西瓜投手碎片",
                "1125": "豌豆荚碎片", "1128": "钢地刺碎片", "1129": "高坚果碎片",
                "1130": "三重射手碎片", "1137": "棱镜草碎片", "1142": "脉冲黄桃碎片",
                "1144": "全息坚果碎片", "1163": "机枪石榴碎片", "1173": "甜薯碎片",
                "1176": "树脂投手碎片", "1178": "火焰豌豆射手碎片", "1182": "眩晕洋葱碎片",
                "1183": "旋转芜菁碎片", "1184": "大王花碎片", "1185": "旋风橡果碎片",
                "1188": "竹小弟碎片", "1189": "漩涡枇杷碎片", "1190": "电离红掌碎片",
                "1192": "飞碟瓜碎片", "1195": "旋转菠萝碎片", "111103": "榴莲碎片",
                "111114": "菠萝蜜碎片", "111127": "大蒜碎片", "111128": "复活萝卜碎片",
                "111137": "香水蘑菇碎片", "111152": "月光花碎片", "111153": "爆炸坚果碎片",
                "111191": "冬瓜守卫碎片", "22000030": "油橄榄碎片", "22000180": "石斛防风网碎片",
                # 蓝色品质
                "1108": "双胞向日葵碎片", "1109": "菜问碎片", "1113": "能量花碎片",
                "1114": "窝瓜碎片", "1117": "火爆辣椒碎片", "1127": "双重射手碎片",
                "1132": "樱桃炸弹碎片", "1139": "激光豆碎片", "1140": "星星果碎片",
                "1141": "三叶草碎片","1147": "胡萝卜导弹车碎片","1151": "魅惑菇碎片", "1160": "橡木弓手碎片",
                "1162": "大力花菜碎片", "1168": "鳄梨碎片", "1169": "导向蓟碎片",
                "1170": "大嘴花碎片", "1174": "竹员外碎片", "1175": "莲小蓬碎片",
                "1177": "飓风甘蓝碎片", "1180": "辣椒投手碎片", "1186": "板栗小队碎片",
                "1191": "芦笋战机碎片", "1198": "玫瑰剑客碎片", "111101": "捣蛋萝卜碎片",
                "111104": "南瓜巫师碎片", "111108": "阿开木木碎片", "111109": "红针花碎片",
                "111111": "岩浆番石榴碎片", "111112": "金蟾菇碎片", "111113": "棉小雪碎片",
                "111115": "龙舌兰碎片", "111117": "梅小美碎片", "111118": "火龙果碎片",
                "111123": "魔音甜菜碎片", "111125": "潜伏芹菜碎片", "111126": "孢子菇碎片",
                "111135": "原始豌豆射手碎片", "111136": "原始坚果碎片", "111138": "原始向日葵碎片",
                "111151": "毒影菇碎片", "111156": "铃儿草投手碎片", "111168": "番莲工程师碎片",
                "22000160": "千金藤碎片", "22000430": "石楠探索者碎片", "22000600": "南瓜头碎片",
                "22001260": "爆浆玉露碎片",
                # 紫色品质
                "1123": "椰子加农炮碎片", "1126": "变身茄子碎片", "1159": "烈焰菇碎片",
                "1161": "蒲公英碎片", "1172": "幽灵辣椒碎片", "1181": "甜菜护卫碎片",
                "1193": "蚕豆突击队碎片", "1199": "电击蓝莓碎片", "111102": "向日葵歌手碎片",
                "111116": "猕猴桃碎片", "111120": "火柴花拳手碎片", "111124": "逆时草碎片",
                "111134": "缩小紫罗兰碎片", "111139": "原始土豆地雷碎片", "111140": "龙吼草碎片",
                "111154": "夜影龙葵碎片", "111158": "暗樱草碎片", "111162": "槲寄冰仙子碎片",
                "111163": "野兽猕猴桃碎片", "111166": "莲藕射手碎片", "111169": "吹风荚兰碎片",
                "111173": "热辣海枣碎片", "111175": "茄子忍者碎片", "111176": "芭蕉舞蹈家碎片",
                "111178": "水仙花射手碎片", "111184": "暗影豌豆碎片", "111186": "水晶兰碎片",
                "111187": "豌豆迫击炮碎片", "111189": "芦荟医师碎片", "22000010": "小黄梨碎片",
                "22000070": "杜英投手碎片", "22000110": "铜钱草鼓手碎片", "22000130": "潜行开口箭碎片",
                "22000140": "暗影荚兰碎片", "22000390": "气流水仙花碎片", "22000500": "黄油毛艮碎片",
                # 橙色品质
                "1112": "火龙草碎片", "1131": "冰西瓜投手碎片", "1143": "充能柚子碎片",
                "1145": "瓷砖萝卜碎片", "1152": "阳光菇碎片", "1158": "寒冰菇碎片",
                "1165": "保龄泡泡碎片", "1167": "香蕉火箭炮碎片", "1171": "强酸柠檬碎片",
                "1197": "魔术菇碎片", "111119": "天使星星果碎片", "111121": "火焰花女王碎片",
                "111122": "机枪射手碎片", "111129": "仙人掌碎片", "111130": "猫尾草碎片",
                "111131": "喇叭花碎片", "111132": "爆裂葡萄碎片", "111133": "冰龙草碎片",
                "111142": "原始大王花碎片", "111143": "蔗师傅碎片", "111144": "玉米加农炮碎片",
                "111145": "苹果迫击炮碎片", "111146": "金缕梅女巫碎片", "111147": "逃脱树根碎片",
                "111148": "电流醋栗碎片", "111149": "白瓜相扑手碎片", "111150": "超能花菜碎片",
                "111155": "幽暮投手碎片", "111160": "炙热山葵碎片", "111161": "防风草碎片",
                "111167": "芦黎药师碎片", "111170": "桑葚爆破手碎片", "111171": "电能豌豆碎片",
                "111172": "寒冰醋栗碎片", "111174": "郁金香号手碎片", "111179": "双枪松果碎片",
                "111181": "警爆磁菇碎片", "111182": "冬青骑士碎片", "111185": "食人花豌豆碎片",
                "111188": "雷龙草碎片", "111190": "熊果臼炮碎片",
                "22000000": "电力绿茶碎片", "22000020": "宝石商石榴碎片", "22000040": "白露花战机碎片",
                "22000050": "爆炸草莓碎片", "22000060": "毒液豌豆射手碎片", "22000080": "飞镖洋蓟碎片",
                "22000090": "荸荠兄弟碎片", "22000100": "尖刺秋葵碎片", "22000120": "终极番茄碎片",
                "22000150": "凤梨链刃碎片", "22000190": "厨师杓兰碎片", "22000200": "粘液桉果碎片",
                "22000210": "橄榄坑碎片", "22000220": "刺眼花艺伎碎片", "22000230": "黏弹糯米碎片",
                "22000240": "地星发射井碎片", "22000250": "奶油生菜碎片", "22000260": "眩晕雏菊碎片",
                "22000270": "爆炸桔梗碎片", "22000280": "庆典汽水椰碎片", "22000290": "钩爪嘉兰碎片",
                "22000310": "凤仙花射手碎片", "22000320": "火鸡投手碎片", "22000330": "铁锤兰碎片",
                "22000340": "聚能山竹碎片", "22000350": "鱼钩草碎片", "22000370": "烈焰火蕨碎片",
                "22000380": "虎头菇碎片", "22000410": "地锯草碎片", "22000440": "树灵护卫碎片",
                "22000450": "疯帽菇碎片", "22000460": "魔法番红花碎片", "22000470": "公主弹簧草碎片",
                "22000480": "突击竹兵碎片", "22000490": "刺果流星锤碎片", "22000510": "激光皇冠花碎片",
                "22000520": "腐尸豆荚碎片", "22000530": "扇贝兰法师碎片", "22000540": "杰克南瓜灯碎片",
                "22000550": "豌豆药剂师碎片", "22000560": "双生卯兔碎片", "22000570": "长枪球兰碎片",
                "22000580": "牛蒡击球手碎片", "22000590": "吸血牛杆菌碎片", "22000610": "鹳草击剑手碎片",
                "22000620": "蓄电雪松果碎片", "22000630": "电能藤蔓碎片", "22000640": "蛇妖瓶子草碎片",
                "22000650": "流星花碎片", "22000660": "曼德拉草碎片", "22000670": "深渊海葵碎片",
                "22000680": "深渊魔爪花碎片", "22000690": "粉丝心叶兰碎片", "22000700": "豌豆藤蔓碎片",
                "22000710": "蜜蜂铃兰碎片", "22000720": "油菜花碎片", "22000730": "剑叶龙血树碎片",
                "22000740": "斯巴达竹碎片", "22000750": "闪耀藤蔓碎片", "22000760": "阳光韭菜碎片",
                "22000770": "暗夜菇碎片", "22000780": "柴堆藤蔓碎片", "22000790": "贪吃龙草碎片",
                "22000800": "兔极碎片", "22000820": "蝎尾蕉机枪手碎片", "22000830": "电鳗香蕉碎片",
                "22000840": "荆棘巫师碎片", "22000850": "锯齿锦地罗碎片", "22000860": "寄生仙钗碎片",
                "22000880": "暴君火龙果碎片", "22000890": "小暴君火龙果碎片", "22000900": "忧郁藤蔓碎片",
                "22000910": "电击鹰爪花碎片", "22000920": "留声曼陀罗碎片", "22000930": "疯狂炮仗花碎片",
                "22000940": "日月金银花碎片", "22000950": "蛮族大黄碎片", "22000960": "水生藤蔓碎片",
                "22000970": "寒霜白毛丹碎片", "22000980": "电击钩吻碎片", "22000990": "寒冰地刺碎片",
                "22001000": "珊瑚泡泡姬碎片", "22001010": "百宝兜兰碎片", "22001020": "女娲蛇尾草碎片",
                "22001270": "枫影剑客碎片","22001280": "守卫菇碎片",
            # 红色品质
            "22000810": "植甲拼装者-炎星碎片"
            }
碎片品质字典 = {
                # 白色品质
                "1101": "白", "1102": "白", "1103": "白", "1104": "白", "1105": "白", 
                "1106": "白", "1110": "白", "1111": "白", "1115": "白", "1118": "白",
                "1121": "白", "1133": "白", "1134": "白", "1135": "白", "1136": "白",
                "1149": "白", "1150": "白", "1153": "白", "1154": "白", "1155": "白",
                "1156": "白", "1157": "白", "1164": "白", "1166": "白", "1179": "白",
                "1194": "白", "111106": "白", "111110": "白", "111141": "白", "111164": "白",
                "111165": "白", "22000170": "白", "22000300": "白",

                # 绿色品质
                "1107": "绿", "1116": "绿", "1119": "绿", "1120": "绿", "1122": "绿",
                "1124": "绿", "1125": "绿", "1128": "绿", "1129": "绿", "1130": "绿",
                "1137": "绿", "1142": "绿", "1144": "绿", "1163": "绿", "1173": "绿",
                "1176": "绿", "1178": "绿", "1182": "绿", "1183": "绿", "1184": "绿",
                "1185": "绿", "1188": "绿", "1189": "绿", "1190": "绿", "1192": "绿",
                "1195": "绿", "111103": "绿", "111114": "绿", "111127": "绿", "111128": "绿",
                "111137": "绿", "111152": "绿", "111153": "绿", "111191": "绿", "22000030": "绿",
                "22000180": "绿",

                # 蓝色品质
                "1108": "蓝", "1109": "蓝", "1113": "蓝", "1114": "蓝", "1117": "蓝",
                "1127": "蓝", "1132": "蓝", "1139": "蓝", "1140": "蓝", "1141": "蓝",
                "1151": "蓝", "1160": "蓝", "1162": "蓝", "1168": "蓝", "1169": "蓝",
                "1170": "蓝", "1174": "蓝", "1175": "蓝", "1177": "蓝", "1180": "蓝",
                "1186": "蓝", "1191": "蓝", "1198": "蓝", "111101": "蓝", "111104": "蓝",
                "111108": "蓝", "111109": "蓝", "111111": "蓝", "111112": "蓝", "111113": "蓝",
                "111115": "蓝", "111117": "蓝", "111118": "蓝", "111123": "蓝", "111125": "蓝",
                "111126": "蓝", "111135": "蓝", "111136": "蓝", "111138": "蓝", "111151": "蓝",
                "111156": "蓝", "111168": "蓝", "22000160": "蓝", "22000430": "蓝", "22000600": "蓝",
                "22001260": "蓝",

                # 紫色品质
                "1123": "紫", "1126": "紫", "1159": "紫", "1161": "紫", "1172": "紫",
                "1181": "紫", "1193": "紫", "1199": "紫", "111102": "紫", "111116": "紫",
                "111120": "紫", "111124": "紫", "111134": "紫", "111139": "紫", "111140": "紫",
                "111154": "紫", "111158": "紫", "111162": "紫", "111163": "紫", "111166": "紫",
                "111169": "紫", "111173": "紫", "111175": "紫", "111176": "紫", "111178": "紫",
                "111184": "紫", "111186": "紫", "111187": "紫", "111189": "紫", "22000010": "紫",
                "22000070": "紫", "22000110": "紫", "22000130": "紫", "22000140": "紫", "22000390": "紫",
                "22000500": "紫",

                # 橙色品质
                "1112": "橙", "1131": "橙", "1143": "橙", "1145": "橙", "1152": "橙",
                "1158": "橙", "1165": "橙", "1167": "橙", "1171": "橙", "1197": "橙",
                "111119": "橙", "111121": "橙", "111122": "橙", "111129": "橙", "111130": "橙",
                "111131": "橙", "111132": "橙", "111133": "橙", "111142": "橙", "111143": "橙",
                "111144": "橙",
                "111145": "橙", "111146": "橙", "111147": "橙", "111148": "橙", "111149": "橙",
            "111150": "橙", "111155": "橙", "111160": "橙", "111161": "橙", "111167": "橙",
            "111170": "橙", "111171": "橙", "111172": "橙", "111174": "橙", "111179": "橙",
            "111181": "橙", "111182": "橙", "111185": "橙", "111188": "橙", "111190": "橙",
            "22000000": "橙", "22000020": "橙", "22000040": "橙", "22000050": "橙", "22000060": "橙",
            "22000080": "橙", "22000090": "橙", "22000100": "橙", "22000120": "橙", "22000150": "橙",
            "22000190": "橙", "22000200": "橙", "22000210": "橙", "22000220": "橙", "22000230": "橙",
            "22000240": "橙", "22000250": "橙", "22000260": "橙", "22000270": "橙", "22000280": "橙",
            "22000290": "橙", "22000310": "橙", "22000320": "橙", "22000330": "橙", "22000340": "橙",
            "22000350": "橙", "22000370": "橙", "22000380": "橙", "22000410": "橙", "22000440": "橙",
            "22000450": "橙", "22000460": "橙", "22000470": "橙", "22000480": "橙", "22000490": "橙",
            "22000510": "橙", "22000520": "橙", "22000530": "橙", "22000540": "橙", "22000550": "橙",
            "22000560": "橙", "22000570": "橙", "22000580": "橙", "22000590": "橙", "22000610": "橙",
            "22000620": "橙", "22000630": "橙", "22000640": "橙", "22000650": "橙", "22000660": "橙",
            "22000670": "橙", "22000680": "橙", "22000690": "橙", "22000700": "橙", "22000710": "橙",
            "22000720": "橙", "22000730": "橙", "22000740": "橙", "22000750": "橙", "22000760": "橙",
            "22000770": "橙", "22000780": "橙", "22000790": "橙", "22000800": "橙", "22000820": "橙",
            "22000830": "橙", "22000840": "橙", "22000850": "橙", "22000860": "橙", "22000880": "橙",
            "22000890": "橙", "22000900": "橙", "22000910": "橙", "22000920": "橙", "22000930": "橙",
            "22000940": "橙", "22000950": "橙", "22000960": "橙", "22000970": "橙", "22000980": "橙",
            "22000990": "橙", "22001000": "橙", "22001010": "橙", "22001020": "橙", "22001270": "橙",
            "22000120": "橙",
"22000520": "橙",
"22000530": "橙",
"22000540": "橙",
"22000550": "橙",
"22000560": "橙",
"22000570": "橙",
"22000580": "橙",
"22000590": "橙",
"22000610": "橙",
"22000620": "橙",
"22000630": "橙",
"22000640": "橙",
"22000650": "橙",
"22000660": "橙",
"22000670": "橙",
"22000680": "橙",
"22000690": "橙",
"22000700": "橙",
"22000710": "橙",
"22000720": "橙",
"22000730": "橙",
"22000740": "橙",
"22000750": "橙",
"22000760": "橙",
"22000770": "橙",
"22000780": "橙",
"22000790": "橙",
"22000800": "橙",
"22000820": "橙",
"22000830": "橙",
"22000840": "橙",
"22000850": "橙",
"22000860": "橙",
"22000880": "橙",
"22000890": "橙",
"22000900": "橙",
"22000910": "橙",
"22000920": "橙",
"22000930": "橙",
"22000940": "橙",
"22000950": "橙",
"22000960": "橙",
"22000970": "橙",
"22000980": "橙",
"22000990": "橙",
"22001000": "橙",
"22001010": "橙",
"22001020": "橙",
"22001270": "橙",
           # 红色品质
            "22000810": "植甲拼装者-炎星碎片"
            }
碎片颜色字典 = {
    "白": Fore.WHITE,
    "绿": Fore.GREEN,
    "蓝": Fore.BLUE,
    "紫": Fore.MAGENTA,
    "橙": Fore.YELLOW,
    "红": Fore.RED
}

双人对决僵尸字典 = {
    "404000": "普通僵尸",
    "404001": "小鸡",
    "404002": "读报二爷僵尸",
    "404003": "机枪僵尸",
    "404004": "全明星僵尸",
    "404005": "电磁盾僵尸",
    "404006": "章鱼法师僵尸",
    "404007": "铜人僵尸",
    "404008": "铁桶僵尸",
    "404009": "矿工僵尸",
    "404010": "冰鼬",
    "404011": "投罐车僵尸",
    "404012": "路障僵尸",
    "404013": "火把僵尸",
    "404015": "机器牛僵尸",
    "404016": "魔法师僵尸",
    "404017": "气球僵尸",
    "404018": "飞行器僵尸",
    "404019": "爆炸坚果僵尸",
    "404020": "巨人僵尸",
    "404021": "冰砖僵尸",
    "404022": "寒冰豌豆僵尸",
    "404023": "贝壳僵尸",
    "404024": "侏罗纪野人僵尸",
    "404025": "铲子僵尸",
    "404026": "小鬼气球僵尸",
    "404027": "渡渡鸟僵尸",
    "404028": "冲浪板僵尸",
    "404029": "辣椒僵尸",
    "404030": "神风僵尸",
    "404031": "喝酒僵尸",
    "404032": "盗贼僵尸",
    "404033": "玩具车僵尸",
    "404034": "自爆僵尸",
    "404035": "治愈者僵尸",
    "404036": "忍者小鬼僵尸",
    "404037": "猎人僵尸",
    "404038": "周刊二爷僵尸",
    "404039": "失落阳伞僵尸",
    "404040": "冰风酋长僵尸",
    "404041": "机甲路障僵尸",
    "404042": "失落考古学家僵尸",
    "404043": "绅士僵尸",
    "404044": "穴居僵尸",
    "404045": "闪动僵尸",
    "404046": "大刀武僧僵尸",
    "404047": "火把武僧僵尸",
    "404048": "鸡贼僵尸",
    "404049": "小丑僵尸",
    "404050": "朋克僵尸",
    "404051": "石像僵尸",
    "404052": "恶龙小鬼僵尸",
    "404053": "花火僵尸",
    "404054": "功夫铜锣僵尸",
    "404055": "骑兵僵尸",
    "404056": "蜻蜓僵尸",
    "404057": "海盗船长僵尸",
    "404058": "锤子僵尸",
    "404059": "失落医生僵尸",
    "404060": "功夫气功僵尸",
    "404061": "农夫僵尸",
    "404062": "死神僵尸",
    "404063": "滚筒僵尸",
    "404064": "淘金僵尸",
    "404065": "霹雳舞僵尸"
}

植物品质字典 = {
    '1001': '白', '1002': '白', '1003': '白', '1004': '白', '1005': '白', 
    '1006': '白', '1110': '白', '1111': '白', '1115': '白', '1118': '白',
    '1121': '白', '1133': '白', '1134': '白', '1135': '白', '1136': '白',  
    '1149': '白', '1150': '白', '1153': '白', '1154': '白', '1155': '白',
    '1156': '白', '1157': '白', '1164': '白', '1166': '白', '1179': '白',
    '1194': '白', '111106': '白', '111110': '白', '111141': '白', '111164': '白',
    '111165': '白', '22000170': '白', '22000300': '白',
    # 绿色品质
    '1007': '绿', '1116': '绿', '1119': '绿', '1120': '绿', '1122': '绿', 
    '1024': '绿', '1025': '绿', '1028': '绿', '1029': '绿', '1030': '绿',
    '1037': '绿', '1047': '绿', '1062': '绿', '1063': '绿', '1073': '绿',
    '1074': '绿', '1075': '绿', '1076': '绿', '1078': '绿', '1079': '绿',
    '1082': '绿', '1083': '绿', '1085': '绿', '1088': '绿', '1089': '绿',
    '1095': '绿', '111014': '绿', '111027': '绿', '111028': '绿', '111042': '绿',
    '111052': '绿', '111053': '绿',
    # 蓝色品质
    '1008': '蓝', '1009': '蓝', '1013': '蓝', '1014': '蓝', '1017': '蓝',
    '1027': '蓝', '1032': '蓝', '1039': '蓝', '1040': '蓝', '1041': '蓝',
    '1044': '蓝', '1050': '蓝', '1051': '蓝', '1068': '蓝', '1069': '蓝',
    '1070': '蓝', '1077': '蓝', '1080': '蓝', '1090': '蓝', '1091': '蓝',
    '1098': '蓝', '111001': '蓝', '111004': '蓝', '111008': '蓝', '111012': '蓝', 
    '111013': '蓝', '111015': '蓝', '111017': '蓝', '111018': '蓝', '111023': '蓝',
    '111025': '蓝', '111026': '蓝', '111035': '蓝', '111038': '蓝', '111054': '蓝',
    '111055': '蓝', '111056': '蓝', '111066': '蓝', '111089': '蓝', '200008': '蓝',
    '200015': '蓝', '200043': '蓝', '200060': '蓝',
    # 紫色品质
    '1023': '紫', '1026': '紫', '1059': '紫', '1060': '紫', '1061': '紫',
    '1072': '紫', '1081': '紫', '1093': '紫', '1099': '紫', '111002': '紫',
    '111009': '紫', '111011': '紫', '111016': '紫', '111020': '紫', '111024': '紫',
    '111034': '紫', '111036': '紫', '111039': '紫', '111040': '紫', '111058': '紫',
    '111062': '紫', '111063': '紫', '111069': '紫', '111073': '紫', '111074': '紫',
    '111076': '紫', '111078': '紫', '111086': '紫', '111087': '紫', '200001': '紫',
    '200011': '紫', '200013': '紫', '200014': '紫', '200033': '紫', '200039': '紫',
    # 橙色品质
    '1012': '橙', '1031': '橙', '1043': '橙', '1045': '橙', '1052': '橙',
    '1058': '橙', '1065': '橙', '1067': '橙', '1071': '橙', '1084': '橙',
    '1097': '橙', '111019': '橙', '111021': '橙', '111022': '橙', '111029': '橙',
    '111030': '橙', '111031': '橙', '111032': '橙', '111033': '橙', '111043': '橙',
    '111044': '橙', '111045': '橙', '111046': '橙', '111047': '橙', '111048': '橙',
    '111049': '橙', '111050': '橙', '111051': '橙', '111060': '橙', '111061': '橙',
    '111067': '橙', '111070': '橙', '111071': '橙', '111072': '橙', '111075': '橙',
    '111079': '橙', '111081': '橙', '111082': '橙', '111084': '橙', '111085': '橙',
    '111088': '橙', '111090': '橙', '200000': '橙', '200002': '橙', '200003': '橙',
    '200004': '橙', '200005': '橙', '200006': '橙', '200007': '橙', '200009': '橙',
    '200010': '橙', '200012': '橙', '200018': '橙', '200019': '橙', '200020': '橙',
    '200021': '橙', '200022': '橙', '200023': '橙', '200024': '橙', '200025': '橙',
    '200026': '橙', '200027': '橙', '200028': '橙', '200029': '橙', '200031': '橙',
    '200032': '橙', '200034': '橙', '200035': '橙', '200037': '橙', '200038': '橙',
    '200041': '橙', '200044': '橙', '200045': '橙', '200046': '橙', '200047': '橙',
    '200048': '橙', '200049': '橙', '200050': '橙', '200051': '橙', '200052': '橙',
    '200053': '橙', '200054': '橙', '200055': '橙', '200056': '橙', '200057': '橙',
    '200058': '橙', '200059': '橙', '200061': '橙', '200062': '橙', '200063': '橙',
    '200064': '橙', '200065': '橙', '200066': '橙', '200067': '橙', '200068': '橙',
    '200069': '橙', '200070': '橙', '200071': '橙', '200072': '橙', '200073': '橙',
    '200074': '橙', '200075': '橙', '200076': '橙', '200077': '橙', '200078': '橙',
    '200079': '橙', '200080': '橙', '200082': '橙', '200083': '橙', '200084': '橙',
    '200085': '橙', '200086': '橙', '200088': '橙', '200089': '橙', '200090': '橙',
    '200091': '橙', '200092': '橙', '200093': '橙', '200094': '橙', '200095': '橙',
    '200096': '橙', '200097': '橙', '200098': '橙', '200099': '橙', '200100': '橙',
    '200101': '橙', '200102': '橙', '200126': '橙', '200127': '橙',
    # 红色品质
    '200081': '红'
}

神器字典 = {
    "60001": "神风神器",
    "60002": "闪电神器",
    "60003": "投罐神器",
    "60004": "治愈神器",
    "60005": "护盾神器",
    "60006": "章鱼神器",
    "60007": "街机神器",
    "60008": "时间神器",
    "60009": "窜天猴神器",
    "60010": "扭蛋神器",
    "60011": "魔豆神器",
    "60012": "飞碟神器",
    "60013": "退化神器",
    "60014": "棱镜塔神器",
    "60015": "恐龙号角神器",
    "60016": "水枪神器",
    "60017": "黑洞神器",
    "60018": "陨石神器",
    "60019": "魔法帽神器",
    "60020": "蜂巢神器",
    "60021": "进化神器",
    "60022": "点金神器",
    "60023": "酸液神器",
    "60024": "制雪神器",
    "60025": "滑板神器",
    "60026": "摇滚神器",
    "60027": "银之键神器",
    "60028": "龙灯神器",
    "60029": "三叉戟神器",
    "60030": "葫芦神器",
    "60031": "一窝蜂神器",
    "60032": "全息神器",
    "60033": "摄魂神器",
    "60034": "相机神器",
    "60035": "超重力神器",
    "60036": "液压神器",}

道具字典 = {"23007": "白色培养液",
    "23008": "绿色培养液",
    "23009": "蓝色培养液",
    "23010": "紫色培养液",
    "23011": "橙色培养液",
    "23036": "紫金币",
    "23037": "限时夺宝奖杯",
    "23046": "进阶书",
    "23091": "大剧院币",
    "23093": "追击币",
    "23094": "时空水晶",
    "23095": "时空粉尘",
    "23097": "红水晶",
    "23098": "秘宝券",
    "23111": "心愿抽奖券",
    "23112": "时空能量罐",
    "23114": "时空能量罐",
    "23115": "时空能量罐",
    "23113": "时空立方",
    "23116": "时空立方",
    "23117": "时空立方",
    "23123": "普通神器祝福券",
    "23124": "高级神器祝福券",
    "23140": "基因源质",
    "23141": "基因币",
    "23225": "万能碎片",
    "23226": "定向碎片",
    "23238": "嘉年华兑换券",
    "23243": "双人对决紫币",
    "23285": "聚宝盆兑换币",
    "23289": "装扮券",
    "23306": "聚宝盆金币",
    "23361": "龙晶",
    "23362": "龙族宝库积分",
    "23365": "绿色植物两片自选",
    "23367": "绿色植物三片自选",
    "23369": "蓝色植物两片自选",
    "23371": "蓝色植物三片自选",
    "23373": "紫色植物两片自选",
    "23375": "紫色植物三片自选",
    "23379": "蓝色自选",
    "23381": "紫色自选",
    "23383": "橙色自选",
    "23385": "花盆自选",
    "23387": "超级自选",
    "23394": "雕像",
    "23395": "幸运宝箱2期",
    "23396": "僵博蓝水晶",
    "23397": "许愿池币",
    "23398": "邀新邀请券",
    "23399": "鞭炮",
    "23400": "黄色蜗牛币",
    "23401": "彩色蜗牛币",
    "23402": "庭院黄币",
    "23403": "庭院紫币",
    "23406": "初级年货装扮箱子",
    "23411": "同游友谊币",
    "23412": "元宝大作战元宝",
    "23414": "黑洞",
    "23415": "42号秘境黄币",
    "23416": "42号秘境彩色币",
    "23420": "派对助力券",
    "23421": "时空礼盒金币",
    "23423": "中级年货装扮箱子",
    "23424": "高级年货装扮箱子",
    "23425": "戴夫厨房玉米",
    "23426": "戴夫厨房水",
    "23427": "戴夫厨房蔬菜",
    "23428": "戴夫厨房牛肉",
    "3008": "钻石",
    "4013": "金币",
    "2209": "黄瓜",
    "3010": "戴夫券",
    "300005": "国风怀古行绿水晶",
    "300037": "火晶",
	"22001": "金肥料碎片",
	"22002": "金铁桶碎片",
	"22003": "加速花盆碎片",
	"22004": "金医药箱碎片",
	"22005": "聚光花盆碎片",
	"22006": "金闹钟碎片",
	"22007": "太阳能花盆碎片",
	"22008": "金火药桶碎片",
	"22009": "火把碎片",
	"22010": "雪花挂坠碎片",
	"22011": "电线杆碎片",
	"22012": "小黄鸭游泳圈碎片",
	"22013": "紫肥料碎片",
	"22014": "紫铁桶碎片",
	"22015": "紫医药箱碎片",
	"22016": "紫闹钟碎片",
	"22017": "紫火药桶碎片",
	"22018": "紫火把碎片",
	"22019": "紫雪花碎片",
	"22020": "紫电线杆碎片",
	"22021": "蓝肥料碎片",
	"22022": "蓝铁桶碎片",
	"22023": "蓝医药箱碎片",
	"22024": "蓝火把碎片",
	"22025": "蓝雪花挂坠碎片",
	"22026": "蓝电线杆碎片",
	"22027": "绿肥料碎片",
	"22028": "绿铁桶碎片",
	"22029": "绿医药箱碎片",
	"22030": "节能罐碎片",
	"73001": "豌豆射手基因",
	"73002": "坚果墙基因",
	"73003": "向日葵基因",
	"73004": "土豆雷基因",
	"73005": "卷心菜基因",
	"73006": "冰冻生菜基因",
    "73007": "地刺基因",
    "73008": "双向射手基因",
    "73009": "玉米投手基因",
    "73010": "火葫芦基因",
    "73011": "白萝卜基因",
    "73012": "竹笋基因",
    "73013": "小喷菇基因",
    "73014": "大喷菇基因",
    "73015": "阳光豆基因",
    "73016": "花生射手基因",
    "73017": "黄金蓓蕾基因",
    "73018": "磁力菇基因",
    "73019": "仙桃基因",
    "73020": "大丽菊基因",
    "73021": "寒冰射手基因",
    "73022": "闪电芦苇基因",
    "73023": "西瓜投手基因",
    "73024": "地刺王基因",
    "73025": "高坚果基因",
    "73026": "三线射手基因",
    "73027": "棱镜草基因",
    "73028": "甜薯基因",
    "73029": "脉冲黄桃基因",
    "73030": "月光花基因",
    "73031": "爆炸坚果基因",
    "73032": "冬瓜守卫基因",
    "73033": "榴莲基因",
    "73034": "树脂投手基因",
    "73035": "大王花基因",
    "73036": "复活萝卜基因",
    "73037": "大蒜基因",
    "73038": "飞碟瓜基因",
    "73039": "原始豌豆射手基因",
    "73040": "樱桃炸弹基因",
    "73041": "激光豆基因",
    "73042": "星星果基因",
    "73043": "全息坚果基因",
    "73044": "大嘴花基因",
    "73045": "南瓜巫师基因",
    "73046": "三叶草基因",
    "73047": "菜问基因",
    "73048": "能量花基因",
    "73049": "魔音甜菜基因",
    "73050": "飓风甘蓝基因",
    "73051": "双胞向日葵基因",
    "73052": "原始向日葵基因",
    "73053": "板栗小队基因",
    "73054": "金蝉菇基因",
    "73055": "豌豆迫击炮基因",
    "73056": "变身茄子基因",
    "73057": "电击蓝莓基因",
    "73058": "向日葵歌手基因",
    "73059": "甜菜护卫基因",
    "73060": "杜英投手基因",
    "73061": "热辣海枣基因",
    "73062": "芦荟医师基因",
    "73063": "猕猴桃基因",
    "73064": "蚕豆突击队基因",
    "73065": "害羞紫罗兰基因",
    "73066": "气流水仙花基因",
    "73067": "暗影豌豆基因",
    "73068": "爆炸桔梗基因",
    "73069": "瓷砖萝卜基因",
    "73070": "聚能山竹基因",
    "73071": "机枪射手基因",
    "73072": "桑葚爆破手基因",
    "73073": "牛蒡击球手基因",
    "73074": "猫尾草基因",
    "73075": "熊果臼炮基因",
    "73076": "火龙草基因",
    "73077": "冰龙草基因",
    "73078": "超能花菜基因",
    "73079": "魔术菇基因",
    "73080": "橄榄坑基因",
    "73081": "弹簧豆基因",
    "73082": "路灯花基因",
    "73083": "火炬树桩基因",
    "73084": "豌豆荚基因",
    "73085": "南瓜头基因",
    "73086": "岩浆番石榴基因",
    "73087": "槲寄冰仙子基因",
    "73088": "小黄梨基因",
    "73089": "冰瓜投手基因",
    "73090": "双生卯兔基因",
    "73091": "缠绕水草基因",
    "73092": "巴豆基因",
    "73093": "火焰豌豆基因",
    "73094": "旋转菠萝基因",
    "73095": "石楠探索者基因",
    "73096": "倭瓜基因",
    "73097": "刺果流星锤基因",
    "73098": "黄油毛茛基因",
    "73099": "长枪球兰基因",
    "73100": "豌豆药剂师基因",
    "73101": "滴水冰莲基因",
    "73102": "黄金叶基因",
    "73103": "回旋镖射手基因",
    "73104": "电离红掌基因",
    "73105": "导向蓟基因",
    "73106": "龙舌兰基因",
    "73107": "铜钱草鼓手基因",
    "73108": "逆时草基因",
    "73109": "仙人掌基因",
    "73110": "激光皇冠花基因",
	"83001": "商店豌豆射手基因",
	"83002": "商店坚果墙基因",
	"83003": "商店向日葵基因",
	"83004": "商店土豆雷基因",
	"83005": "商店卷心菜基因",
	"83006": "商店冰冻生菜基因",
    "83007": "商店地刺基因",
    "83008": "商店双向射手基因",
    "83009": "商店玉米投手基因",
    "83010": "商店火葫芦基因",
    "83011": "商店白萝卜基因",
    "83012": "商店竹笋基因",
    "83013": "商店小喷菇基因",
    "83014": "商店大喷菇基因",
    "83015": "商店阳光豆基因",
    "83016": "商店花生射手基因",
    "83017": "商店黄金蓓蕾基因",
    "83018": "商店磁力菇基因",
    "83019": "商店仙桃基因",
    "83020": "商店大丽菊基因",
    "83021": "商店寒冰射手基因",
    "83022": "商店闪电芦苇基因",
    "83023": "商店西瓜投手基因",
    "83024": "商店地刺王基因",
    "73025": "商店高坚果基因",
    "83026": "商店三线射手基因",
    "73027": "商店棱镜草基因",
    "83028": "商店甜薯基因",
    "83029": "商店脉冲黄桃基因",
    "83030": "商店月光花基因",
    "83031": "商店爆炸坚果基因",
    "83032": "商店冬瓜守卫基因",
    "83033": "商店榴莲基因",
    "83034": "商店树脂投手基因",
    "83035": "商店大王花基因",
    "83036": "商店复活萝卜基因",
    "83037": "商店大蒜基因",
    "73038": "商店飞碟瓜基因",
    "83039": "商店原始豌豆射手基因",
    "73040": "商店樱桃炸弹基因",
    "43041": "商店激光豆基因",
    "83042": "商店星星果基因",
    "83043": "商店全息坚果基因",
    "83044": "商店大嘴花基因",
    "83045": "商店南瓜巫师基因",
    "83046": "商店三叶草基因",
    "83047": "商店菜问基因",
    "83048": "商店能量花基因",
    "83049": "商店魔音甜菜基因",
    "73050": "商店飓风甘蓝基因",
    "83051": "商店双胞向日葵基因",
    "83052": "商店原始向日葵基因",
    "83053": "商店板栗小队基因",
    "83054": "商店金蝉菇基因",
    "83055": "商店豌豆迫击炮基因",
    "83056": "商店变身茄子基因",
    "83057": "商店电击蓝莓基因",
    "83058": "商店向日葵歌手基因",
    "83059": "商店甜菜护卫基因",
    "73060": "商店杜英投手基因",
    "73061": "商店热辣海枣基因",
    "83062": "商店芦荟医师基因",
    "83063": "商店猕猴桃基因",
    "83064": "商店蚕豆突击队基因",
    "83065": "商店害羞紫罗兰基因",
    "83066": "商店气流水仙花基因",
    "83067": "商店暗影豌豆基因",
    "83068": "商店爆炸桔梗基因",
    "83069": "商店瓷砖萝卜基因",
    "83070": "商店聚能山竹基因",
    "83071": "商店机枪射手基因",
    "83072": "商店桑葚爆破手基因",
    "73073": "商店牛蒡击球手基因",
    "83074": "商店猫尾草基因",
    "73075": "商店熊果臼炮基因",
    "83076": "商店火龙草基因",
    "73077": "商店冰龙草基因",
    "83078": "商店超能花菜基因",
    "73079": "商店魔术菇基因",
    "83080": "商店橄榄坑基因",
    "83081": "商店弹簧豆基因",
    "83082": "商店路灯花基因",
    "83083": "商店火炬树桩基因",
    "83084": "商店豌豆荚基因",
    "83085": "商店南瓜头基因",
    "83086": "商店岩浆番石榴基因",
    "83087": "商店槲寄冰仙子基因",
    "83088": "商店小黄梨基因",
    "83089": "商店冰瓜投手基因",
    "73090": "商店双生卯兔基因",
    "83091": "商店缠绕水草基因",
    "83092": "商店巴豆基因",
    "83093": "商店火焰豌豆基因",
    "83094": "商店旋转菠萝基因",
    "83095": "商店石楠探索者基因",
    "83096": "商店倭瓜基因",
    "83097": "商店刺果流星锤基因",
    "83098": "商店黄油毛茛基因",
    "83099": "商店长枪球兰基因",
    "73100": "商店豌豆药剂师基因",
    "83101": "商店滴水冰莲基因",
    "83102": "商店黄金叶基因",
    "73103": "商店回旋镖射手基因",
    "83104": "商店电离红掌基因",
    "83105": "商店导向蓟基因",
    "83106": "商店龙舌兰基因",
    "83107": "商店铜钱草鼓手基因",
    "83108": "商店逆时草基因",
    "73109": "商店仙人掌基因",
    "83110": "商店激光皇冠花基因"
    }

植物装扮碎片字典 = {"1301": "豌豆射手伴生装扮碎片",
    "1302": "向日葵伴生装扮碎片",
    "1303": "坚果伴生装扮碎片",
    "1304": "土豆地雷伴生装扮碎片",
    "1305": "卷心菜投手伴生装扮碎片",
    "1306": "冰冻生菜伴生装扮碎片",
    "1307": "回旋镖射手伴生装扮碎片",
    "1308": "双胞向日葵伴生装扮碎片",
    "1309": "菜问伴生装扮碎片",
    "1310": "弹簧豆伴生装扮碎片",
    "1311": "地刺伴生装扮碎片",
    "1312": "火龙草伴生装扮碎片",
    "1313": "能量花伴生装扮碎片",
    "1314": "窝瓜伴生装扮碎片",
    "1315": "巴豆伴生装扮碎片",
    "1316": "双向射手伴生装扮碎片",
    "1317": "火爆辣椒伴生装扮碎片",
    "1318": "噬碑藤伴生装扮碎片",
    "1319": "寒冰豌豆伴生装扮碎片",
    "1320": "火炬树桩伴生装扮碎片",
    "1321": "玉米投手伴生装扮碎片",
    "1322": "闪电芦苇伴生装扮碎片",
    "1323": "椰子加农炮伴生装扮碎片",
    "1324": "西瓜投手伴生装扮碎片",
    "1325": "豌豆荚伴生装扮碎片",
    "1326": "变身茄子伴生装扮碎片",
    "1327": "双重射手伴生装扮碎片",
    "1328": "钢地刺伴生装扮碎片",
    "1329": "高坚果伴生装扮碎片",
    "1330": "三重射手伴生装扮碎片",
    "1331": "冰西瓜投手伴生装扮碎片",
    "1332": "樱桃炸弹伴生装扮碎片",
    "1333": "仙桃伴生装扮碎片",
    "1334": "火葫芦伴生装扮碎片",
    "1335": "白萝卜伴生装扮碎片",
    "1336": "竹笋伴生装扮碎片",
    "1337": "棱镜草伴生装扮碎片",
    "1339": "激光豆伴生装扮碎片",
    "1340": "星星果伴生装扮碎片",
    "1341": "三叶草伴生装扮碎片",
    "1342": "脉冲黄桃伴生装扮碎片",
    "1343": "充能柚子伴生装扮碎片",
    "1344": "全息坚果伴生装扮碎片",
    "1345": "瓷砖萝卜伴生装扮碎片",
    "1347": "胡萝卜导弹车伴生装扮碎片",
    "1349": "小喷菇伴生装扮碎片",
    "1350": "大喷菇伴生装扮碎片",
    "1351": "魅惑菇伴生装扮碎片",
    "1352": "阳光菇伴生装扮碎片",
    "1353": "阳光豆伴生装扮碎片",
    "1354": "花生射手伴生装扮碎片",
    "1355": "磁力菇伴生装扮碎片",
    "1356": "路灯花伴生装扮碎片",
    "1357": "咖啡豆伴生装扮碎片",
    "1358": "寒冰菇伴生装扮碎片",
    "1359": "烈焰菇伴生装扮碎片",
    "1360": "橡木弓手伴生装扮碎片",
    "1361": "蒲公英伴生装扮碎片",
    "1362": "大力花菜伴生装扮碎片",
    "1363": "机枪石榴伴生装扮碎片",
    "1364": "莲叶伴生装扮碎片",
    "1365": "保龄泡泡伴生装扮碎片",
    "1366": "缠绕水草伴生装扮碎片",
    "1367": "香蕉火箭炮伴生装扮碎片",
    "1368": "鳄梨伴生装扮碎片",
    "1369": "导向蓟伴生装扮碎片",
    "1370": "大嘴花伴生装扮碎片",
    "1371": "强酸柠檬伴生装扮碎片",
    "1372": "幽灵辣椒伴生装扮碎片",
    "1373": "甜薯伴生装扮碎片",
    "1374": "竹员外伴生装扮碎片",
    "1375": "莲小蓬伴生装扮碎片",
    "1376": "树脂投手伴生装扮碎片",
    "1377": "飓风甘蓝伴生装扮碎片",
    "1378": "火焰豌豆射手伴生装扮碎片",
    "1379": "烤马铃薯伴生装扮碎片",
    "1380": "辣椒投手伴生装扮碎片",
    "1381": "甜菜护卫伴生装扮碎片",
    "1382": "眩晕洋葱伴生装扮碎片",
    "1383": "旋转芜菁伴生装扮碎片",
    "1384": "大王花伴生装扮碎片",
    "1385": "旋风橡果伴生装扮碎片",
    "1386": "板栗小队伴生装扮碎片",
    "1388": "竹小弟伴生装扮碎片",
    "1389": "漩涡枇杷伴生装扮碎片",
    "1390": "电离红掌伴生装扮碎片",
    "1391": "芦笋战机伴生装扮碎片",
    "1392": "飞碟瓜伴生装扮碎片",
    "1393": "蚕豆突击队伴生装扮碎片",
    "1394": "灯笼草伴生装扮碎片",
    "1395": "旋转菠萝伴生装扮碎片",
    "1397": "魔术菇伴生装扮碎片",
    "1398": "玫瑰剑客伴生装扮碎片",
    "1399": "电击蓝莓伴生装扮碎片",
    "111301": "捣蛋萝卜伴生装扮碎片",
    "111302": "向日葵歌手伴生装扮碎片",
    "111303": "榴莲伴生装扮碎片",
    "111304": "南瓜巫师伴生装扮碎片",
    "111306": "黄金叶伴生装扮碎片",
    "111308": "阿开木木伴生装扮碎片",
    "111309": "红针花伴生装扮碎片",
    "111310": "大丽菊伴生装扮碎片",
    "111311": "岩浆番石榴伴生装扮碎片",
    "111312": "金蟾菇伴生装扮碎片",
    "111313": "棉小雪伴生装扮碎片",
    "111314": "菠萝蜜伴生装扮碎片",
    "111315": "龙舌兰伴生装扮碎片",
    "111316": "猕猴桃伴生装扮碎片",
    "111317": "梅小美伴生装扮碎片",
    "111318": "火龙果伴生装扮碎片",
    "111319": "天使星星果伴生装扮碎片",
    "111320": "火柴花拳手伴生装扮碎片",
    "111321": "火焰花女王伴生装扮碎片",
    "111322": "机枪射手伴生装扮碎片",
    "111323": "魔音甜菜伴生装扮碎片",
    "111324": "逆时草伴生装扮碎片",
    "111325": "潜伏芹菜伴生装扮碎片",
    "111326": "孢子菇伴生装扮碎片",
    "111327": "大蒜伴生装扮碎片",
    "111328": "复活萝卜伴生装扮碎片",
    "111329": "仙人掌伴生装扮碎片",
    "111330": "猫尾草伴生装扮碎片",
    "111331": "喇叭花伴生装扮碎片",
    "111332": "爆裂葡萄伴生装扮碎片",
    "111333": "冰龙草伴生装扮碎片",
    "111334": "缩小紫罗兰伴生装扮碎片",
    "111335": "原始豌豆射手伴生装扮碎片",
    "111336": "原始坚果伴生装扮碎片",
    "111337": "香水蘑菇伴生装扮碎片",
    "111338": "原始向日葵伴生装扮碎片",
    "111339": "原始土豆地雷伴生装扮碎片",
    "111340": "龙吼草伴生装扮碎片",
    "111341": "胆小荆棘伴生装扮碎片",
    "111342": "原始大王花伴生装扮碎片",
    "111343": "蔗师傅伴生装扮碎片",
    "111344": "玉米加农炮伴生装扮碎片",
    "111345": "苹果迫击炮伴生装扮碎片",
    "111346": "金缕梅女巫伴生装扮碎片",
    "111347": "逃脱树根伴生装扮碎片",
    "111348": "电流醋栗伴生装扮碎片",
    "111349": "白瓜相扑手伴生装扮碎片",
    "111350": "超能花菜伴生装扮碎片",
    "111351": "毒影菇伴生装扮碎片",
    "111352": "月光花伴生装扮碎片",
    "111353": "爆炸坚果伴生装扮碎片",
    "111354": "夜影龙葵伴生装扮碎片",
    "111355": "幽暮投手伴生装扮碎片",
    "111356": "铃儿草投手伴生装扮碎片",
    "111358": "暗樱草伴生装扮碎片",
    "111360": "炙热山葵伴生装扮碎片",
    "111361": "防风草伴生装扮碎片",
    "111362": "槲寄冰仙子伴生装扮碎片",
    "111363": "野兽猕猴桃伴生装扮碎片",
    "111364": "黄金蓓蕾伴生装扮碎片",
    "111365": "平顶菇伴生装扮碎片",
    "111366": "莲藕射手伴生装扮碎片",
    "111367": "芦黎药师伴生装扮碎片",
    "111368": "番莲工程师伴生装扮碎片",
    "111369": "吹风荚兰伴生装扮碎片",
    "111370": "桑葚爆破手伴生装扮碎片",
    "111371": "电能豌豆伴生装扮碎片",
    "111372": "寒冰醋栗伴生装扮碎片",
    "111373": "热辣海枣伴生装扮碎片",
    "111374": "郁金香号手伴生装扮碎片",
    "111375": "茄子忍者伴生装扮碎片",
    "111376": "芭蕉舞蹈家伴生装扮碎片",
    "111378": "水仙花射手伴生装扮碎片",
    "111379": "双枪松果伴生装扮碎片",
    "111381": "警爆磁菇伴生装扮碎片",
    "111382": "冬青骑士伴生装扮碎片",
    "111384": "暗影豌豆伴生装扮碎片",
    "111385": "食人花豌豆伴生装扮碎片",
    "111386": "水晶兰伴生装扮碎片",
    "111387": "豌豆迫击炮伴生装扮碎片",
    "111388": "雷龙草伴生装扮碎片",
    "111389": "芦荟医师伴生装扮碎片",
    "111390": "熊果臼炮伴生装扮碎片",
    "111391": "冬瓜守卫伴生装扮碎片",
    "42000000": "电力绿茶伴生装扮碎片",
    "42000010": "小黄梨伴生装扮碎片",
    "42000020": "宝石商石榴伴生装扮碎片",
    "42000030": "油橄榄伴生装扮碎片",
    "42000040": "白露花战机伴生装扮碎片",
    "42000050": "爆炸草莓伴生装扮碎片",
    "42000060": "毒液豌豆射手伴生装扮碎片",
    "42000070": "杜英投手伴生装扮碎片",
    "42000080": "飞镖洋蓟伴生装扮碎片",
    "42000090": "荸荠兄弟伴生装扮碎片",
    "42000100": "尖刺秋葵伴生装扮碎片",
    "42000110": "铜钱草鼓手伴生装扮碎片",
    "42000120": "终极番茄伴生装扮碎片",
    "42000130": "潜行开口箭伴生装扮碎片",
    "42000140": "暗影荚兰伴生装扮碎片",
    "42000150": "凤梨链刃伴生装扮碎片",
    "42000160": "千金藤伴生装扮碎片",
    "42000170": "滴水冰莲伴生装扮碎片",
    "42000180": "石斛防风网伴生装扮碎片",
    "42000190": "厨师杓兰伴生装扮碎片",
    "42000200": "粘液桉果伴生装扮碎片",
    "42000210": "橄榄坑伴生装扮碎片",
    "42000220": "刺眼花艺伎伴生装扮碎片",
    "42000230": "黏弹糯米伴生装扮碎片",
    "42000240": "地星发射井伴生装扮碎片",
    "42000250": "奶油香菜伴生装扮碎片",
    "42000260": "眩晕雏菊伴生装扮碎片",
    "42000270": "爆炸桔梗伴生装扮碎片",
    "42000280": "庆典汽水椰伴生装扮碎片",
    "42000290": "钩爪嘉兰伴生装扮碎片",
    "42000300": "花盆伴生装扮碎片",
    "42000310": "凤仙花射手伴生装扮碎片",
    "42000320": "火鸡投手伴生装扮碎片",
    "42000330": "铁锤兰伴生装扮碎片",
    "42000340": "聚能山竹伴生装扮碎片",
    "42000350": "鱼钩草伴生装扮碎片",
    "42000370": "烈焰火蕨伴生装扮碎片",
    "42000380": "虎头菇伴生装扮碎片",
    "42000390": "气流水仙花伴生装扮碎片",
    "42000410": "地锯草伴生装扮碎片",
    "42000430": "石楠探索者伴生装扮碎片",
    "42000440": "树灵护卫伴生装扮碎片",
    "42000450": "疯帽菇伴生装扮碎片",
    "42000460": "魔法番红花伴生装扮碎片",
    "42000470": "公主弹簧草伴生装扮碎片",
    "42000480": "宊击竹兵伴生装扮碎片",
    "42000490": "刺果流星锤伴生装扮碎片",
    "42000500": "黄油毛艮伴生装扮碎片",
    "42000510": "激光皇冠花伴生装扮碎片",
    "42000520": "腐尸豆荚伴生装扮碎片",
    "42000530": "扇贝兰法师伴生装扮碎片",
    "42000540": "杰克南瓜灯伴生装扮碎片",
    "42000550": "豌豆药剂师伴生装扮碎片",
    "42000560": "双生卯兔伴生装扮碎片",
    "42000570": "长枪球兰伴生装扮碎片",
    "42000580": "牛蒡击球手伴生装扮碎片",
    "42000590": "吸血牛杆菌伴生装扮碎片",
    "42000600": "南瓜头伴生装扮碎片",
    "42000610": "鹳草击剑手伴生装扮碎片",
    "42000620": "蓄电雪松果伴生装扮碎片",
    "42000630": "电能藤蔓伴生装扮碎片",
    "42000640": "蛇妖瓶子草伴生装扮碎片",
    "42000650": "流星花伴生装扮碎片",
    "42000660": "曼德拉草伴生装扮碎片",
    "42000670": "深渊海葵伴生装扮碎片",
    "42000680": "深渊魔爪花伴生装扮碎片",
    "42000690": "粉丝心叶兰伴生装扮碎片",
    "42000700": "豌豆藤蔓伴生装扮碎片",
    "42000710": "蜜蜂铃兰伴生装扮碎片",
    "42000720": "油菜花伴生装扮碎片",
    "42000730": "剑叶龙血树伴生装扮碎片",
    "42000740": "斯巴达竹伴生装扮碎片",
    "42000750": "闪耀藤蔓伴生装扮碎片",
    "42000760": "阳光韭菜伴生装扮碎片",
    "42000770": "暗夜菇伴生装扮碎片",
    "42000780": "柴堆藤蔓伴生装扮碎片",
    "42000790": "贪吃龙草伴生装扮碎片",
    "42000800": "兔极伴生装扮碎片",
    "42000810": "植甲拼装者-炎星伴生装扮碎片",
    "42000820": "蝎尾蕉机枪手伴生装扮碎片",
    "42000830": "电鳗香蕉伴生装扮碎片",
    "42000840": "荆棘巫师伴生装扮碎片",
    "42000850": "锯齿锦地罗伴生装扮碎片",
    "42000860": "寄生仙钗伴生装扮碎片",
    "42000880": "暴君火龙果伴生装扮碎片",
    "42000890": "小暴君火龙果伴生装扮碎片",
    "42000900": "忧郁藤蔓伴生装扮碎片",
    "42000910": "电击鹰爪花伴生装扮碎片",
    "42000920": "留声曼陀罗伴生装扮碎片",
    "42000930": "疯狂炮仗花伴生装扮碎片",
    "42000940": "日月金银花伴生装扮碎片",
    "42000950": "蛮族大黄伴生装扮碎片",
    "42000960": "水生藤蔓伴生装扮碎片",
    "42000970": "寒霜白毛丹伴生装扮碎片",
    "42000980": "电击钩吻伴生装扮碎片",
    "42000990": "寒冰地刺伴生装扮碎片",
    "42001000": "珊瑚泡泡姬伴生装扮碎片",
    "42001010": "百宝兜兰伴生装扮碎片",
    "42001020": "女娲蛇尾草伴生装扮碎片",
    "42001260": "爆浆玉露伴生装扮碎片",
    "42001270": "枫影刺客伴生装扮碎片",
    "42001280": "守卫菇伴生装扮碎片",
    "40010011": "豌豆射手春节装扮碎片",
    "40010012": "豌豆射手圣诞装扮碎片",
    "40010013": "豌豆射手飞车装扮碎片",
    "40010021": "向日葵海盗船长装扮碎片",
    "40010022": "向日葵六一装扮碎片",
    "40010023": "向日葵万圣装扮碎片",
    "40010024": "向日葵圣诞节装扮碎片",
    "40010025": "向日葵联动装扮碎片",
    "40010031": "坚果大胡子装扮碎片",
    "40010032": "坚果绷带装扮碎片",
    "40010041": "土豆海绵眼睛装扮碎片",
    "40010042": "土豆虎年鞭炮装扮碎片",
    "40010053": "卷心菜投手春节装扮碎片",
    "40010054": "卷心菜投手头饰装扮碎片",
    "40010061": "冰冻生菜复古耳罩碎片",
    "40010062": "冰冻生菜豌豆耳罩碎片",
    "40010071": "回旋镖射手彩蛋帽碎片",
    "40010072": "回旋镖射手飞侠帽碎片",
    "40010081": "双胞向日葵礼帽碎片",
    "40010082": "双胞向日葵超级装扮碎片",
    "40010091": "菜问春节衣服碎片",
    "40010092": "菜问牛年帽子碎片",
    "40010093": "菜问万圣绷带装扮碎片",
    "40010101": "弹簧豆草裙碎片",
    "40010121": "火龙草钢盔碎片",
    "40010122": "火龙草礼帽碎片",
    "40010123": "火龙草兔耳帽碎片",
    "40010124": "火龙草龙年装扮碎片",
    "40010131": "能量花周年装扮碎片",
    "40010141": "窝瓜头带二装碎片",
    "40010142": "窝瓜飞车装扮碎片",
    "40010151": "巴豆围巾碎片",
    "40010161": "双向射手圣与魔头饰碎片",
    "40010191": "寒冰射手绿色绒线帽碎片",
    "40010192": "寒冰射手棉帽碎片",
    "40010193": "寒冰射手永劫无间侠帽碎片",
    "40010201": "火炬树桩蓝色泳镜碎片",
    "40010211": "玉米投手加油头带碎片",
    "40010213": "玉米投手绅士衣服碎片",
    "40010221": "闪电芦苇兔耳帽碎片",
    "40010222": "闪电芦苇绅士礼帽碎片",
    "40010231": "椰子加农炮复古帽碎片",
    "40010232": "椰子加农炮礼帽帽碎片",
    "40010241": "西瓜投手水手帽碎片",
    "40010242": "西瓜投手礼帽碎片",
    "40010244": "西瓜投手盒子帽碎片",
    "40011251": "豌豆荚3D眼镜碎片",
    "40010271": "双重射手维京帽碎片",
    "40010273": "双重射手棉帽碎片",
    "40010281": "钢地刺护目镜碎片",
    "40010282": "钢地刺单片镜碎片",
    "40010291": "高坚果学者装扮碎片",
    "40010292": "高坚果六一装扮碎片",
    "40010301": "三重射手铁锅装扮碎片",
    "40010302": "三重射手六一装扮碎片",
    "40010311": "冰西瓜绒帽碎片",
    "40010313": "冰西瓜夹子风扇碎片",
    "40010331": "仙桃永劫无间头饰碎片",
    "40010372": "棱镜草礼帽碎片",
    "40010373": "棱镜草儿童节日礼帽碎片",
    "40010391": "激光豆金链子碎片",
    "40010392": "激光豆六一装扮碎片",
    "40010393": "激光豆周年装扮碎片",
    "40010401": "星星果假发碎片",
    "40010421": "脉冲黄桃万圣装扮碎片",
    "40010431": "充能柚子冰杯帽碎片",
    "40010441": "全息坚果面包机装扮碎片",
    "40010442": "全息坚果周年装扮碎片",
    "40010451": "瓷砖萝卜超级装扮",
    "40010491": "小喷菇周年庆装扮碎片",
    "40010501": "大喷菇舞狮头装扮碎片",
    "40010521": "阳光菇唐僧帽子装扮碎片",
    "40010551": "磁力菇棋盘格装扮碎片",
    "40010581": "寒冰菇金秋装扮碎片",
    "40010691": "导向蓟六一装扮碎片",
    "40010701": "大嘴花春节装扮碎片",
    "40010702": "大嘴花周年装扮碎片",
    "40010703": "大嘴花超级装扮碎片",
    "40010711": "强酸柠檬圣诞装扮碎片",
    "40010721": "幽灵辣椒灯笼装扮碎片",
    "40010781": "火焰豌豆周年装扮碎片",
    "40010811": "甜菜护卫腰带碎片",
    "40010812": "甜菜护卫虎年装扮碎片",
    "40010821": "眩晕洋葱飞行套装碎片",
    "40010831": "旋转芜菁望远镜头带碎片",
    "40010861": "板栗小队六一装扮碎片",
    "40010931": "蚕豆突击队六一装扮碎片",
    "40010932": "蚕豆突击队飞车装扮碎片",
    "40010991": "电击蓝莓三孔插座帽碎片",
    "41110011": "捣蛋萝卜六一装扮碎片",
    "41110021": "向日葵歌手虎年装扮碎片",
    "41110022": "向日葵歌手六一装扮碎片",
    "41110023": "向日葵歌手奥运装扮碎片",
    "41110031": "榴莲球衣碎片",
    "41110041": "南瓜巫师万圣装扮碎片",
    "41110081": "阿开木木头带碎片",
    "41110091": "红针花探险帽碎片",
    "41110101": "大丽菊面具碎片",
    "41110111": "岩浆番石榴花圈碎片",
    "41110121": "金蟾菇爆炸头装扮碎片",
    "41110141": "菠萝蜜六一装扮碎片",
    "41110142": "菠萝蜜搞怪眼罩装扮碎片",
    "41110151": "龙舌兰春节装扮碎片",
    "41110161": "猕猴桃气球金箍碎片",
    "41110162": "猕猴桃围巾碎片",
    "41110163": "猕猴桃全身装扮碎片",
    "41110191": "天使星星果眼镜碎片",
    "41110192": "天使星星果全身装扮碎片",
    "41110221": "机枪豌豆联动装扮碎片",
    "41110222": "机枪豌豆限定装扮碎片",
    "41110231": "魔音甜菜兔年DJ围巾碎片",
    "41110251": "潜伏芹菜斗士盔碎片",
    "41110261": "孢子菇蓝色折纸帽碎片",
    "41110271": "大蒜硅胶手套碎片",
    "41110291": "仙人掌派对助力装扮碎片",
    "41110301": "猫尾草小型快递纸箱碎片",
    "41110302": "猫尾草蛋糕头装扮碎片",
    "41110321": "爆裂葡萄彩气球碎片",
    "41110331": "冰龙草冰激凌装扮碎片",
    "41110332": "冰龙草龙年装扮碎片",
    "41110351": "原始豌豆射手浴帽碎片",
    "41110352": "原始豌豆射手春节装扮碎片",
    "41110353": "原始豌豆射手河姆渡头罐碎片",
    "41110354": "原始豌豆射手锦衣卫全身装扮碎片",
    "41110361": "原始坚果墙泳装碎片",
    "41110362": "原始坚果墙蜜帝全身装扮碎片",
    "41110381": "原始向日葵恐龙帽碎片",
    "41110382": "原始向日葵河姆渡陶罐碎片",
    "41110391": "原始土豆地雷虎纹装扮碎片",
    "41110401": "龙吼草联动装扮碎片",
    "41110431": "蔗师傅联动装扮碎片",
    "41110441": "玉米加农炮圣诞帽碎片",
    "41110451": "苹果迫击炮虎年装扮碎片",
    "41110452": "苹果迫击炮成长装扮碎片",
    "41110453": "苹果迫击炮派对助力装扮碎片",
    "41110461": "金缕梅女巫睡帽碎片",
    "41110471": "逃脱树根警长帽碎片",
    "41110481": "电流醋栗节能灯碎片",
    "41110521": "月光花周年庆装扮碎片",
    "41110531": "爆炸坚果星星眼镜碎片",
    "41110551": "幽暮投手鸭舌帽碎片",
    "41110561": "铃儿草投手蝴蝶结碎片",
    "41110611": "防风草蟹壳帽碎片",
    "41110621": "槲寄冰仙子围巾碎片",
    "41110622": "斛寄冰仙子周年装扮碎片",
    "41110641": "黄金蓓蕾周年装扮碎片",
    "41110671": "芦黎药师成长装扮碎片",
    "41110672": "芦黎药师超级装扮碎片",
    "41110691": "吹风荚兰儿童高筒帽碎片",
    "41110631": "野兽猕猴桃头饰碎片",
    "41110701": "桑葚爆破手周年庆假面装扮碎片",
    "41110702": "桑葚爆破手成长海盗眼罩碎片",
    "41110703": "桑葚爆破手限时召唤海盗装扮碎片",
    "41110711": "电能豌豆成长装扮碎片",
    "41110751": "茄子忍者圣诞装扮碎片",
    "41110752": "茄子忍者成长装扮碎片",
    "41110753": "茄子忍者零装扮碎片",
    "41110791": "双枪松果兔年装扮碎片",
    "41110821": "冬青骑士福字装扮碎片",
    "41110841": "暗影豌豆女巫帽碎片",
    "41110842": "暗影豌豆草帽碎片",
    "41110851": "食人花豌豆成长装扮碎片",
    "41110861": "水晶兰圣诞装扮碎片",
    "41110871": "豌豆迫击炮周年庆装扮碎片",
    "41110872": "豌豆迫击炮金秋装扮碎片",
    "41110881": "雷龙草兔年装扮碎片",
    "41110882": "雷龙草龙年装扮碎片",
    "41110891": "芦荟医师战旗套装碎片",
    "41110892": "芦荟医师周年装扮碎片",
    "41110901": "熊果臼炮周年庆装扮碎片",
    "41110902": "熊果臼炮成长装扮碎片",
    "42000011": "小黄梨兔年装扮碎片",
    "42000012": "小黄梨禅杖装扮碎片",
    "42000071": "杜英投手六一装扮碎片",
    "42000072": "杜英投手周年装扮碎片",
    "42000073": "杜英投手永劫无间装扮碎片",
    "42000091": "荸荠兄弟虎年装扮碎片",
    "42000092": "荸荠兄弟成长装扮碎片",
    "42000101": "尖刺秋葵娃娃假发碎片",
    "42000111": "铜钱草鼓手兔年装扮碎片",
    "42000171": "滴水冰莲联动装扮碎片",
    "42000191": "厨师杓兰六一装扮碎片",
    "42000192": "厨师杓兰成长装扮碎片",
    "42000211": "橄榄坑成长装扮碎片",
    "42000212": "橄榄坑搞怪眼镜装扮碎片",
    "42000241": "地星发射井金秋装扮碎片",
    "42000261": "眩晕雏菊眩晕眼镜装扮碎片",
    "42000271": "爆炸桔梗圣诞节装扮碎片",
    "42000321": "火鸡投手圣诞节装扮碎片",
    "42000322": "火鸡投手奶嘴装扮碎片",
    "42000341": "聚能山竹发卡碎片",
    "42000342": "聚能山竹飞车头碎片",
    "42000343": "聚能山竹全身装扮碎片",
    "42000371": "烈焰火蕨舞会假面装扮碎片",
    "42000372": "烈焰火蕨哪吒装扮碎片",
    "42000381": "虎头菇成长装扮碎片",
    "42000382": "虎头菇永劫无间联动装扮碎片",
    "42000391": "气流水仙花成长装扮碎片",
    "42000511": "激光皇冠花圣诞大胡子碎片",
    "42000512": "激光皇冠花成长装扮碎片",
    "42000513": "激光皇冠花女王装扮碎片",
    "42000531": "扇贝兰成长装扮碎片",
    "42000532": "扇贝兰派对助力装扮碎片",
    "42000561": "双生卯兔成长装扮碎片",
    "42000571": "长枪秋兰龙年装扮碎片",
    "42000581": "牛蒡击球手成长装扮碎片",
    "42000582": "牛蒡击球手全身装扮碎片",
    "42000601": "南瓜头全身装扮碎片",
    "42000611": "鹳草击剑手龙年装扮碎片",
    "42000621": "蓄电雪松果成长装扮碎片",
    "42000641": "蛇妖瓶子草成长装扮碎片",
    "42000661": "曼德拉草成长装扮碎片",
    "42000662": "曼德拉草派对助力装扮碎片",
    "42000671": "深渊海葵成长装扮碎片",
    "42000681": "深渊魔爪花成长装扮碎片",
    "42000691": "粉丝心叶兰圣诞装扮碎片",
    "42000692": "粉丝心叶兰飞车装扮碎片",
    "42000731": "剑叶龙血树成长装扮碎片",
    "42000732": "剑叶龙血树永劫无间联动装扮碎片",
    "42000733": "剑叶龙血树红衣服装扮碎片",
    "42000741": "斯巴达竹成长装扮碎片",
    "42000771": "暗夜菇成长装扮碎片",
    "42000791": "贪吃龙草成长装扮碎片",
    "42000792": "贪吃龙草超级装扮碎片",
    "42000801": "兔极企鹅装扮碎片",
    "42000821": "蝎尾蕉机枪手成长装扮碎片",
    "42000831": "电鳗香蕉派对助力装扮碎片",
    "42000832": "电鳗香蕉超级装扮碎片",
    "42000841": "荆棘巫师成长装扮碎片",
    "42000851": "锯齿锦地罗成长装扮碎片",
    "42000861": "寄生仙钗成长装扮碎片",
    "42000881": "暴君火龙果成长装扮碎片",
    "42000911": "电击鹰爪花飞车装扮碎片",
    "42000921": "留声曼陀罗金秋装扮碎片",
    "42000922": "留声曼陀罗成长装扮碎片",
    "42000941": "日月金银花冬日装扮碎片",
    "42000951": "蛮族大黄成长装扮碎片",
    "42000981": "电击钩吻派对助力眼镜装扮碎片",
    "42000982": "电击钩吻成长装扮碎片",
    "42001011": "百宝兜兰丞相帽子装扮碎片",
    "42001021": "女娲蛇尾草全身装扮碎片"}

家族字典 = {
    "50001": "新人组",
    "50002": "光芒万丈",
    "50003": "不动如山",
    "50004": "真能打",
    "50005": "我要打十个",
    "50006": "火力全开",
    "50007": "冰力四射",
    "50008": "雷霆万钧",
    "50009": "能量武器",
    "50010": "精英豌豆",
    "50011": "军火库",
    "50012": "三分王",
    "50013": "神射手",
    "50014": "百步穿僵",
    "50015": "人多力量大",
    "50016": "踩僵尸的蘑菇",
    "50017": "暗影家族",
    "50018": "环保卫士",
    "50019": "文艺青年",
    "50020": "忍者小队",
    "50021": "大厨组合",
    "50022": "摧枯拉朽",
    "50023": "坚固防线",
    "50024": "控场大师",
    "50025": "魔法大师",
    "50026": "枝繁叶茂",
    "50027": "十二生肖",
    "50028": "繁花似锦",
    "50029": "打飞他们",
    "50030": "十万伏特",
    "50031": "动物世界",
    "50032": "炸个痛快",
    "50033": "小心脚下",
    "50034": "惊声尖笑",
    "50035": "运动健将",
    "50036": "不如跳舞",
    "50037": "头有点晕",
    "50038": "酸甜苦辣",
    "50039": "武林对决",
    "50040": "地爆天星",
    "50041": "光暗交织",
    "50042": "亿点控制",
    "50043": "冰与火",
    "50044": "未来科技",
    "50045": "花开富贵",
    "50046": "火力压制",
    "50047": "群卜荟萃"
}

属性字典 = {
    "extra_sunmoney_50": "额外产出50阳光",
    "extra_sunmoney_25": "额外产出25阳光",
    "extra_hitpoints": "生命值增加",
    "extra_attack": "攻击力增加",
    "regeneration": "每5秒恢复生命",
    "lower_cost": "阳光消耗降低",
    "fast_plant": "种植冷却缩短",
    "improved_atk_rate": "攻击速度增加",
    "improved_explode_damage": "爆炸伤害增加",
    "improved_flame_damage": "火焰伤害增加",
    "improved_cold_damage": "冰冻伤害增加",
    "improved_lightning_damage": "闪电伤害增加",
    "invincible": "无敌3秒概率",
    "ghost": "灵魂状态概率",
    "plant_sun_refund": "返还阳光概率",
    "extra_defend": "防御力增加",
    "extra_melee_attack": "近战伤害增加",
    "improved_sunproduce_rate": "生产速度增加"
}

植物装扮字典 = {"1201": "豌豆射手伴生装扮",
    "1202": "向日葵伴生装扮",
    "1203": "坚果伴生装扮",
    "1204": "土豆地雷伴生装扮",
    "1205": "卷心菜投手伴生装扮",
    "1206": "冰冻生菜伴生装扮",
    "1207": "回旋镖射手伴生装扮",
    "1208": "双胞向日葵伴生装扮",
    "1209": "菜问伴生装扮",
    "1210": "弹簧豆伴生装扮",
    "1211": "地刺伴生装扮",
    "1212": "火龙草伴生装扮",
    "1213": "能量花伴生装扮",
    "1214": "窝瓜伴生装扮",
    "1215": "巴豆伴生装扮",
    "1216": "双向射手伴生装扮",
    "1217": "火爆辣椒伴生装扮",
    "1218": "噬碑藤伴生装扮",
    "1219": "寒冰豌豆伴生装扮",
    "1220": "火炬树桩伴生装扮",
    "1221": "玉米投手伴生装扮",
    "1222": "闪电芦苇伴生装扮",
    "1223": "椰子加农炮伴生装扮",
    "1224": "西瓜投手伴生装扮",
    "1225": "豌豆荚伴生装扮",
    "1226": "变身茄子伴生装扮",
    "1227": "双重射手伴生装扮",
    "1228": "钢地刺伴生装扮",
    "1229": "高坚果伴生装扮",
    "1230": "三重射手伴生装扮",
    "1231": "冰西瓜投手伴生装扮",
    "1232": "樱桃炸弹伴生装扮",
    "1233": "仙桃伴生装扮",
    "1234": "火葫芦伴生装扮",
    "1235": "白萝卜伴生装扮",
    "1236": "竹笋伴生装扮",
    "1237": "棱镜草伴生装扮",
    "1239": "激光豆伴生装扮",
    "1240": "星星果伴生装扮",
    "1241": "三叶草伴生装扮",
    "1242": "脉冲黄桃伴生装扮",
    "1243": "充能柚子伴生装扮",
    "1244": "全息坚果伴生装扮",
    "1245": "瓷砖萝卜伴生装扮",
    "1247": "胡萝卜导弹车伴生装扮",
    "1249": "小喷菇伴生装扮",
    "1250": "大喷菇伴生装扮",
    "1251": "魅惑菇伴生装扮",
    "1252": "阳光菇伴生装扮",
    "1253": "阳光豆伴生装扮",
    "1254": "花生射手伴生装扮",
    "1255": "磁力菇伴生装扮",
    "1256": "路灯花伴生装扮",
    "1257": "咖啡豆伴生装扮",
    "1258": "寒冰菇伴生装扮",
    "1259": "烈焰菇伴生装扮",
    "1260": "橡木弓手伴生装扮",
    "1261": "蒲公英伴生装扮",
    "1262": "大力花菜伴生装扮",
    "1263": "机枪石榴伴生装扮",
    "1264": "莲叶伴生装扮",
    "1265": "保龄泡泡伴生装扮",
    "1266": "缠绕水草伴生装扮",
    "1267": "香蕉火箭炮伴生装扮",
    "1268": "鳄梨伴生装扮",
    "1269": "导向蓟伴生装扮",
    "1270": "大嘴花伴生装扮",
    "1271": "强酸柠檬伴生装扮",
    "1272": "幽灵辣椒伴生装扮",
    "1273": "甜薯伴生装扮",
    "1274": "竹员外伴生装扮",
    "1275": "莲小蓬伴生装扮",
    "1276": "树脂投手伴生装扮",
    "1277": "飓风甘蓝伴生装扮",
    "1278": "火焰豌豆射手伴生装扮",
    "1279": "烤马铃薯伴生装扮",
    "1280": "辣椒投手伴生装扮",
    "1281": "甜菜护卫伴生装扮",
    "1282": "眩晕洋葱伴生装扮",
    "1283": "旋转芜菁伴生装扮",
    "1284": "大王花伴生装扮",
    "1285": "旋风橡果伴生装扮",
    "1286": "板栗小队伴生装扮",
    "1288": "竹小弟伴生装扮",
    "1289": "漩涡枇杷伴生装扮",
    "1290": "电离红掌伴生装扮",
    "1291": "芦笋战机伴生装扮",
    "1292": "飞碟瓜伴生装扮",
    "1293": "蚕豆突击队伴生装扮",
    "1294": "灯笼草伴生装扮",
    "1295": "旋转菠萝伴生装扮",
    "1297": "魔术菇伴生装扮",
    "1298": "玫瑰剑客伴生装扮",
    "1299": "电击蓝莓伴生装扮",
    "111201": "捣蛋萝卜伴生装扮",
    "111202": "向日葵歌手伴生装扮",
    "111203": "榴莲伴生装扮",
    "111204": "南瓜巫师伴生装扮",
    "111206": "黄金叶伴生装扮",
    "111208": "阿开木木伴生装扮",
    "111209": "红针花伴生装扮",
    "111210": "大丽菊伴生装扮",
    "111211": "岩浆番石榴伴生装扮",
    "111212": "金蟾菇伴生装扮",
    "111213": "棉小雪伴生装扮",
    "111214": "菠萝蜜伴生装扮",
    "111215": "龙舌兰伴生装扮",
    "111216": "猕猴桃伴生装扮",
    "111217": "梅小美伴生装扮",
    "111218": "火龙果伴生装扮",
    "111219": "天使星星果伴生装扮",
    "111220": "火柴花拳手伴生装扮",
    "111221": "火焰花女王伴生装扮",
    "111222": "机枪射手伴生装扮",
    "111223": "魔音甜菜伴生装扮",
    "111224": "逆时草伴生装扮",
    "111225": "潜伏芹菜伴生装扮",
    "111226": "孢子菇伴生装扮",
    "111227": "大蒜伴生装扮",
    "111228": "复活萝卜伴生装扮",
    "111229": "仙人掌伴生装扮",
    "111230": "猫尾草伴生装扮",
    "111231": "喇叭花伴生装扮",
    "111232": "爆裂葡萄伴生装扮",
    "111233": "冰龙草伴生装扮",
    "111234": "缩小紫罗兰伴生装扮",
    "111235": "原始豌豆射手伴生装扮",
    "111236": "原始坚果伴生装扮",
    "111237": "香水蘑菇伴生装扮",
    "111238": "原始向日葵伴生装扮",
    "111239": "原始土豆地雷伴生装扮",
    "111240": "龙吼草伴生装扮",
    "111241": "胆小荆棘伴生装扮",
    "111242": "原始大王花伴生装扮",
    "111243": "蔗师傅伴生装扮",
    "111244": "玉米加农炮伴生装扮",
    "111245": "苹果迫击炮伴生装扮",
    "111246": "金缕梅女巫伴生装扮",
    "111247": "逃脱树根伴生装扮",
    "111248": "电流醋栗伴生装扮",
    "111249": "白瓜相扑手伴生装扮",
    "111250": "超能花菜伴生装扮",
    "111251": "毒影菇伴生装扮",
    "111252": "月光花伴生装扮",
    "111253": "爆炸坚果伴生装扮",
    "111254": "夜影龙葵伴生装扮",
    "111255": "幽暮投手伴生装扮",
    "111256": "铃儿草投手伴生装扮",
    "111258": "暗樱草伴生装扮",
    "111260": "炙热山葵伴生装扮",
    "111261": "防风草伴生装扮",
    "111262": "槲寄冰仙子伴生装扮",
    "111263": "野兽猕猴桃伴生装扮",
    "111264": "黄金蓓蕾伴生装扮",
    "111265": "平顶菇伴生装扮",
    "111266": "莲藕射手伴生装扮",
    "111267": "芦黎药师伴生装扮",
    "111268": "番莲工程师伴生装扮",
    "111269": "吹风荚兰伴生装扮",
    "111270": "桑葚爆破手伴生装扮",
    "111271": "电能豌豆伴生装扮",
    "111272": "寒冰醋栗伴生装扮",
    "111273": "热辣海枣伴生装扮",
    "111274": "郁金香号手伴生装扮",
    "111275": "茄子忍者伴生装扮",
    "111276": "芭蕉舞蹈家伴生装扮",
    "111278": "水仙花射手伴生装扮",
    "111279": "双枪松果伴生装扮",
    "111281": "警爆磁菇伴生装扮",
    "111282": "冬青骑士伴生装扮",
    "111284": "暗影豌豆伴生装扮",
    "111285": "食人花豌豆伴生装扮",
    "111286": "水晶兰伴生装扮",
    "111287": "豌豆迫击炮伴生装扮",
    "111288": "雷龙草伴生装扮",
    "111289": "芦荟医师伴生装扮",
    "111290": "熊果臼炮伴生装扮",
    "111291": "冬瓜守卫伴生装扮",
    "32000000": "电力绿茶伴生装扮",
    "32000010": "小黄梨伴生装扮",
    "32000020": "宝石商石榴伴生装扮",
    "32000030": "油橄榄伴生装扮",
    "32000040": "白露花战机伴生装扮",
    "32000050": "爆炸草莓伴生装扮",
    "32000060": "毒液豌豆射手伴生装扮",
    "32000070": "杜英投手伴生装扮",
    "32000080": "飞镖洋蓟伴生装扮",
    "32000090": "荸荠兄弟伴生装扮",
    "32000100": "尖刺秋葵伴生装扮",
    "32000110": "铜钱草鼓手伴生装扮",
    "32000120": "终极番茄伴生装扮",
    "32000130": "潜行开口箭伴生装扮",
    "32000140": "暗影荚兰伴生装扮",
    "32000150": "凤梨链刃伴生装扮",
    "32000160": "千金藤伴生装扮",
    "32000170": "滴水冰莲伴生装扮",
    "32000180": "石斛防风网伴生装扮",
    "32000190": "厨师杓兰伴生装扮",
    "32000200": "粘液桉果伴生装扮",
    "32000210": "橄榄坑伴生装扮",
    "32000220": "刺眼花艺伎伴生装扮",
    "32000230": "黏弹糯米伴生装扮",
    "32000240": "地星发射井伴生装扮",
    "32000250": "奶油生菜伴生装扮",
    "32000260": "眩晕雏菊伴生装扮",
    "32000270": "爆炸桔梗伴生装扮",
    "32000280": "庆典汽水椰伴生装扮",
    "32000290": "钩爪嘉兰伴生装扮",
    "32000300": "花盆伴生装扮",
    "32000310": "凤仙花射手伴生装扮",
    "32000320": "火鸡投手伴生装扮",
    "32000330": "铁锤兰伴生装扮",
    "32000340": "聚能山竹伴生装扮",
    "32000350": "鱼钩草伴生装扮",
    "32000370": "烈焰火蕨伴生装扮",
    "32000380": "虎头菇伴生装扮",
    "32000390": "气流水仙花伴生装扮",
    "32000410": "地锯草伴生装扮",
    "32000430": "石楠探索者伴生装扮",
    "32000440": "树灵护卫伴生装扮",
    "32000450": "疯帽菇伴生装扮",
    "32000460": "魔法番红花伴生装扮",
    "32000470": "公主弹簧草伴生装扮",
    "32000480": "突击竹兵伴生装扮",
    "32000490": "刺果流星锤伴生装扮",
    "32000500": "黄油毛艮伴生装扮",
    "32000510": "激光皇冠花伴生装扮",
    "32000520": "腐尸豆荚伴生装扮",
    "32000530": "扇贝兰法师伴生装扮",
    "32000540": "杰克南瓜灯伴生装扮",
    "32000550": "豌豆药剂师伴生装扮",
    "32000560": "双生卯兔伴生装扮",
    "32000570": "长枪球兰伴生装扮",
    "32000580": "牛蒡击球手伴生装扮",
    "32000590": "吸血牛杆菌伴生装扮",
    "32000600": "南瓜头伴生装扮",
    "32000610": "鹳草击剑手伴生装扮",
    "32000620": "蓄电雪松果伴生装扮",
    "32000630": "电能藤蔓伴生装扮",
    "32000640": "蛇妖瓶子草伴生装扮",
    "32000650": "流星花伴生装扮",
    "32000660": "曼德拉草伴生装扮",
    "32000670": "深渊海葵伴生装扮",
    "32000680": "深渊魔爪花伴生装扮",
    "32000690": "粉丝心叶兰伴生装扮",
    "32000700": "豌豆藤蔓伴生装扮",
    "32000710": "蜜蜂铃兰伴生装扮",
    "32000720": "油菜花伴生装扮",
    "32000730": "剑叶龙血树伴生装扮",
    "32000740": "斯巴达竹伴生装扮",
    "32000750": "闪耀藤蔓伴生装扮",
    "32000760": "阳光韭菜伴生装扮",
    "32000770": "暗夜菇伴生装扮",
    "32000780": "柴堆藤蔓伴生装扮",
    "32000790": "贪吃龙草伴生装扮",
    "32000800": "兔极伴生装扮",
    "32000810": "植甲拼装者-炎星伴生装扮",
    "32000820": "蝎尾蕉机枪手伴生装扮",
    "32000830": "电鳗香蕉伴生装扮",
    "32000840": "荆棘巫师伴生装扮",
    "32000850": "锯齿锦地罗伴生装扮",
    "32000860": "寄生仙钗伴生装扮",
    "32000880": "暴君火龙果伴生装扮",
    "32000890": "小暴君火龙果伴生装扮",
    "32000900": "忧郁藤蔓伴生装扮",
    "32000910": "电击鹰爪花伴生装扮",
    "32000920": "留声曼陀罗伴生装扮",
    "32000930": "疯狂炮仗花伴生装扮",
    "32000940": "日月金银花伴生装扮",
    "32000950": "蛮族大黄伴生装扮",
    "32000960": "水生藤蔓伴生装扮",
    "32000970": "寒霜白毛丹伴生装扮",
    "32000980": "电击钩吻伴生装扮",
    "32000990": "寒冰地刺伴生装扮",
    "32001000": "珊瑚泡泡姬伴生装扮",
    "32001010": "百宝兜兰伴生装扮",
    "32001020": "女娲蛇尾草伴生装扮",
    "32001260": "爆浆玉露伴生装扮",
    "32001270": "枫影刺客伴生装扮",
    "32001280": "守卫菇伴生装扮",
    "32001330": "伏僵塔黄半生装扮",
    "30010011": "豌豆射手春节装扮",
    "30010012": "豌豆射手圣诞装扮",
    "30010013": "豌豆射手飞车装扮",
    "30010021": "向日葵海盗船长装扮",
    "30010022": "向日葵六一装扮",
    "30010023": "向日葵万圣装扮",
    "30010024": "向日葵圣诞节装扮",
    "30010025": "向日葵联动装扮",
    "30010031": "坚果大胡子装扮",
    "30010032": "坚果绷带装扮",
    "30010041": "土豆海绵眼睛装扮",
    "30010042": "土豆虎年鞭炮装扮",
    "30010053": "卷心菜投手春节装扮",
    "30010054": "卷心菜投手头饰装扮",
    "30010061": "冰冻生菜复古耳罩",
    "30010062": "冰冻生菜豌豆耳罩",
    "30010071": "回旋镖射手彩蛋帽",
    "30010072": "回旋镖射手飞侠帽",
    "30010081": "双胞向日葵礼帽",
    "30010082": "双胞向日葵超级装扮",
    "30010091": "菜问春节衣服",
    "30010092": "菜问牛年帽子",
    "30010093": "菜问万圣绷带装扮",
    "30010101": "弹簧豆草裙",
    "30010121": "火龙草钢盔",
    "30010122": "火龙草礼帽",
    "30010123": "火龙草兔耳帽",
    "30010124": "火龙草龙年装扮",
    "30010131": "能量花周年装扮",
    "30010141": "窝瓜头带二装",
    "30010142": "窝瓜飞车装扮",
    "30010151": "巴豆围巾",
    "30010161": "双向射手圣与魔头饰",
    "30010191": "寒冰射手绿色绒线帽",
    "30010192": "寒冰射手棉帽",
    "30010193": "寒冰射手永劫无间侠帽",
    "30010201": "火炬树桩蓝色泳镜",
    "30010211": "玉米投手加油头带",
    "30010213": "玉米投手绅士衣服",
    "30010221": "闪电芦苇兔耳帽",
    "30010222": "闪电芦苇绅士礼帽",
    "30010231": "椰子加农炮复古帽",
    "30010232": "椰子加农炮礼帽帽",
    "30010241": "西瓜投手水手帽",
    "30010242": "西瓜投手礼帽",
    "30010244": "西瓜投手盒子帽",
    "30011251": "豌豆荚3D眼镜",
    "30010271": "双重射手维京帽",
    "30010273": "双重射手棉帽",
    "30010281": "钢地刺护目镜",
    "30010282": "钢地刺单片镜",
    "30010291": "高坚果学者装扮",
    "30010292": "高坚果六一装扮",
    "30010301": "三重射手铁锅装扮",
    "30010302": "三重射手六一装扮",
    "30010311": "冰西瓜绒帽",
    "30010313": "冰西瓜夹子风扇",
    "30010331": "仙桃永劫无间头饰",
    "30010372": "棱镜草礼帽",
    "30010373": "棱镜草儿童节日礼帽",
    "30010391": "激光豆金链子",
    "30010392": "激光豆六一装扮",
    "30010393": "激光豆周年装扮",
    "30010401": "星星果假发",
    "30010421": "脉冲黄桃万圣装扮",
    "30010431": "充能柚子冰杯帽",
    "30010441": "全息坚果面包机装扮",
    "30010442": "全息坚果周年装扮",
    "30010451": "瓷砖萝卜超级装扮",
    "30010491": "小喷菇周年庆装扮",
    "30010501": "大喷菇舞狮头装扮",
    "30010521": "阳光菇唐僧帽子装扮",
    "30010551": "磁力菇棋盘格装扮",
    "30010581": "寒冰菇金秋装扮",
    "30010691": "导向蓟六一装扮",
    "30010701": "大嘴花春节装扮",
    "30010702": "大嘴花周年装扮",
    "30010703": "大嘴花超级装扮",
    "30010711": "强酸柠檬圣诞装扮",
    "30010721": "幽灵辣椒灯笼装扮",
    "30010781": "火焰豌豆周年装扮",
    "30010811": "甜菜护卫腰带",
    "30010812": "甜菜护卫虎年装扮",
    "30010821": "眩晕洋葱飞行套装",
    "30010831": "旋转芜菁望远镜头带",
    "30010861": "板栗小队六一装扮",
    "30010931": "蚕豆突击队六一装扮",
    "30010932": "蚕豆突击队飞车装扮",
    "30010991": "电击蓝莓三孔插座帽",
    "31110011": "捣蛋萝卜六一装扮",
    "31110021": "向日葵歌手虎年装扮",
    "31110022": "向日葵歌手六一装扮",
    "31110023": "向日葵歌手奥运装扮",
    "31110031": "榴莲球衣",
    "31110041": "南瓜巫师万圣装扮",
    "31110081": "阿开木木头带",
    "31110091": "红针花探险帽",
    "31110101": "大丽菊面具",
    "31110111": "岩浆番石榴花圈",
    "31110121": "金蟾菇爆炸头装扮",
    "31110141": "菠萝蜜六一装扮",
    "31110142": "菠萝蜜搞怪眼罩装扮",
    "31110151": "龙舌兰春节装扮",
    "31110152": "龙舌兰礼帽装扮",
    "31110161": "猕猴桃气球金箍",
    "31110162": "猕猴桃围巾",
    "31110163": "猕猴桃全身装扮",
    "31110164": "猕猴桃齐天大圣装扮",
    "31110171": "梅小美古风装扮",
    "31110191": "天使星星果眼镜",
    "31110192": "天使星星果全身装扮",
    "31110211": "火焰花女王芭蕉扇装扮",
    "31110221": "机枪豌豆联动装扮",
    "31110222": "机枪豌豆限定装扮",
    "31110231": "魔音甜菜兔年DJ围巾",
    "31110251": "潜伏芹菜斗士盔",
    "31110261": "孢子菇蓝色折纸帽",
    "31110271": "大蒜硅胶手套",
    "31110291": "仙人掌派对助力装扮",
    "31110301": "猫尾草小型快递纸箱装扮",
    "31110302": "猫尾草蛋糕头装扮",
    "31110321": "爆裂葡萄彩气球",
    "31110332": "冰龙草龙年装扮",
    "31110331": "冰龙草冰激凌装扮",
    "31110351": "原始豌豆射手浴帽",
    "31110352": "原始豌豆射手春节装扮",
    "31110353": "原始豌豆射手河姆渡头罐",
    "31110354": "原始豌豆锦衣卫全身装扮",
    "31110361": "原始坚果墙泳装",
    "31110362": "原始坚果墙蜜帝全身装扮",
    "31110381": "原始向日葵恐龙帽",
    "31110382": "原始向日葵河姆渡陶罐",
    "31110391": "原始土豆地雷虎纹装扮",
    "31110401": "龙吼草联动装扮",
    "31110431": "蔗师傅联动装扮",
    "31110441": "玉米加农炮圣诞帽",
    "31110451": "苹果迫击炮虎年装扮",
    "31110452": "苹果迫击炮成长装扮",
    "31110453": "苹果迫击炮派对助力装扮",
    "31110461": "金缕梅女巫睡帽",
    "31110471": "逃脱树根警长帽",
    "31110481": "电流醋栗节能灯",
    "31110521": "月光花周年庆装扮",
    "31110531": "爆炸坚果星星眼镜",
    "31110551": "幽暮投手鸭舌帽",
    "31110561": "铃儿草投手蝴蝶结",
    "31110611": "防风草蟹壳帽",
    "31110621": "槲寄冰仙子围巾",
    "31110622": "斛寄冰仙子周年装扮",
    "31110641": "黄金蓓蕾周年装扮",
    "31110671": "芦黎药师成长装扮",
    "31110672": "芦黎药师超级装扮",
    "31110691": "吹风荚兰儿童高筒帽",
    "31110631": "野兽猕猴桃头饰",
    "31110632": "野兽猕猴桃猪八戒装扮",
    "31110701": "桑葚爆破手周年庆假面装扮",
    "31110702": "桑葚爆破手成长海盗眼罩",
    "31110703": "桑葚爆破手限时召唤海盗装扮",
    "31110711": "电能豌豆成长装扮",
    "31110751": "茄子忍者圣诞装扮",
    "31110752": "茄子忍者成长装扮",
    "31110753": "茄子忍者零装扮",
    "31110791": "双枪松果兔年装扮",
    "31110821": "冬青骑士福字装扮",
    "31110841": "暗影豌豆女巫帽",
    "31110842": "暗影豌豆草帽",
    "31110851": "食人花豌豆成长装扮",
    "31110861": "水晶兰圣诞装扮",
    "31110862": "水晶兰唐僧装扮",
    "31110871": "豌豆迫击炮周年庆装扮",
    "31110872": "豌豆迫击炮金秋装扮",
    "31110881": "雷龙草兔年装扮",
    "31110882": "雷龙草龙年装扮",
    "31110892": "芦荟医师周年装扮",
    "31110891": "芦荟医师战旗套装",
    "31110901": "熊果臼炮周年庆装扮",
    "31110902": "熊果臼炮成长装扮",
    "31110903": "熊果臼炮沙僧装扮",
    "32000011": "小黄梨兔年装扮",
    "32000012": "小黄梨禅杖装扮",
    "32000071": "杜英投手六一装扮",
    "32000072": "杜英投手周年装扮",
    "32000073": "杜英投手永劫无间装扮",
    "32000091": "荸荠兄弟虎年装扮",
    "32000092": "荸荠兄弟成长装扮",
    "32000093": "荸荠兄弟金银大王装扮",
    "32000101": "尖刺秋葵娃娃假发",
    "32000111": "铜钱草鼓手兔年装扮",
    "32000171": "滴水冰莲联动装扮",
    "32000191": "厨师杓兰六一装扮",
    "32000192": "厨师杓兰成长装扮",
    "32000211": "橄榄坑成长装扮",
    "32000212": "橄榄坑搞怪眼镜装扮",
    "32000241": "地星发射井金秋装扮",
    "32000261": "眩晕雏菊眩晕眼镜装扮",
    "32000271": "爆炸桔梗圣诞节装扮",
    "32000321": "火鸡投手圣诞节装扮",
    "32000322": "火鸡投手奶嘴装扮",
    "32000341": "聚能山竹发卡装扮",
    "32000342": "聚能山竹飞车装扮",
    "32000343": "聚能山竹全身装扮",
    "32000371": "烈焰火蕨舞会假面装扮",
    "32000372": "烈焰火蕨哪吒全身装扮",
    "32000381": "虎头菇成长装扮",
    "32000382": "虎头菇永劫无间联动装扮",
    "32000391": "气流水仙花成长装扮",
    "32000392": "气流水仙花灯笼装扮",
    "32000511": "激光皇冠花圣诞大胡子装扮",
    "32000512": "激光皇冠花成长装扮",
    "32000513": "激光皇冠花女王装扮",
    "32000531": "扇贝兰成长装扮",
    "32000532": "扇贝兰派对助力装扮",
    "32000561": "双生卯兔成长装扮",
    "32000571": "长枪秋兰龙年装扮",
    "32000572": "长枪秋兰红孩儿装扮",
    "32000581": "牛蒡击球手成长装扮",
    "32000582": "牛蒡击球手全身装扮",
    "32000583": "牛蒡击球手牛魔王装扮",
    "32000601": "南瓜头全身装扮",
    "32000611": "鹳草击剑手龙年装扮",
    "32000621": "蓄电雪松果成长装扮",
    "32000641": "蛇妖瓶子草成长装扮",
    "32000661": "曼德拉草成长装扮",
    "32000662": "曼德拉草派对助力装扮",
    "32000671": "深渊海葵成长装扮",
    "32000681": "深渊魔爪花成长装扮",
    "32000691": "粉丝心叶兰圣诞装扮",
    "32000692": "粉丝心叶兰飞车装扮",
    "32000731": "剑叶龙血树成长装扮",
    "32000732": "剑叶龙血树永劫无间联动装扮",
    "32000733": "剑叶龙血树红衣服装扮",
    "32000741": "斯巴达竹成长装扮",
    "32000771": "暗夜菇成长装扮",
    "32000791": "贪吃龙草成长装扮",
    "32000792": "贪吃龙草超级装扮",
    "32000793": "贪吃龙草龙王装扮",
    "32000801": "兔极企鹅装扮",
    "32000821": "蝎尾蕉机枪手成长装扮",
    "32000831": "电鳗香蕉派对助力装扮",
    "32000832": "电鳗香蕉超级装扮",
    "32000841": "荆棘巫师成长装扮",
    "32000851": "锯齿锦地罗成长装扮",
    "32000861": "寄生仙钗成长装扮",
    "32000881": "暴君火龙果成长装扮",
    "32000911": "电击鹰爪花飞车装扮",
    "32000921": "留声曼陀罗金秋装扮",
    "32000922": "留声曼陀罗成长装扮",
    "32000941": "日月金银花冬日装扮",
    "32000951": "蛮族大黄成长装扮",
    "32000981": "电击钩吻派对助力眼镜装扮",
    "32000982": "电击钩吻成长装扮",
    "32001001": "珊瑚泡泡姬成长装扮",
    "32001011": "百宝兜兰丞相帽子装扮",
    "32001021": "女娲蛇尾草全身装扮"}

url = 'http://cloudpvz2android.ditwan.cn/index.php'
headers = {

    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; 23013RK7C Build/TKQ1.220905.001)',
    'Content-Type': 'multipart/form-data; boundary=_{{}}_',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip'
}
from requests.exceptions import RequestException
def send(data: str, max_retries: int = 5, retry_delay: int = 2):
    """
    发送数据，并包含重试机制。

    :param data: str, 要发送的数据。
    :param max_retries: int, 最大重试次数，默认为3次。
    :param retry_delay: int, 每次重试前的延迟时间（秒），默认为2秒。
    :return: str, 响应文本或错误信息。
    """
    global latency_拓维
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            response = requests.post(url, headers=headers, data=data)
            end_time = time.time()  # 记录请求结束时间
            if response.status_code == 403:
                print("您可能已被拓维锁ip, 请开关飞行模式解除锁定")
                return "ip被锁"
            latency_拓维 = (end_time - start_time) * 1000  # 计算延迟, 并转换为毫秒
            return response.text
        except RequestException as e:
            print(f"发送失败，原因：{e}，正在重试...（剩余重试次数：{max_retries - attempt - 1}）")
            time.sleep(retry_delay)  # 等待一段时间后重试
    # 如果所有重试都失败了，则返回错误信息
    return "发送数据失败，已达到最大重试次数"



# 在发送基础上，增加判断是否成功，并且自动输出拼接语句
def send_for_intent(data: str, intent: str):
    response = send(data)
    success = "\"r\":0" in response
    print(intent, "成功" if success else "失败")
    if not success:
        r_dec = CNNetwork.decrypt(response)
        print(r_dec)
    return success, response

def send_加密发送(plain: dict[str]):
    time.sleep(PACKET_DELAY)
    encrypt = CNNetwork.encrypt(json.dumps(plain, separators=(',', ':')))
    # print(time.strftime("%Y-%m-%d %H:%M:%S"), encrypt)
    response = send(encrypt)
    # print(time.strftime("%Y-%m-%d %H:%M:%S"), response)
    success = "\"r\":0" in response
    return success, response


# 传入明文dict，进行加密并发送，增加判断是否成功，并且自动输出拼接语句
def send_加密发送_拼接提示(plain: dict[str], intent: str):
    time.sleep(PACKET_DELAY)
    suc, r = send_加密发送(plain)
    print(intent, "成功" if suc else "失败")
    if not suc:
        r_dec = CNNetwork.decrypt(r)
        print(r_dec)
    return suc, r


# 传入明文dict，进行加密并发送，返回的密文进行解密并解包到"d"
def send_加密发送_解密响应(plain: dict[str]):
    time.sleep(PACKET_DELAY)
    encrypt = CNNetwork.encrypt(json.dumps(plain, separators=(',', ':')))
    # print(time.strftime("%Y-%m-%d %H:%M:%S"), encrypt)
    response = send(encrypt)
    success = "\"r\":0" in response
    if success:
        r = CNNetwork.decrypt(response)
        # print(time.strftime("%Y-%m-%d %H:%M:%S"), r)
        return success, json.loads(r)["e"]["d"]
    else:
        r = CNNetwork.decrypt(response)
        print(r)
        return False, {}

# 传入明文dict，进行加密并发送，返回的密文进行解密并解包到"d"
def send_发送_解密响应(plain: dict[str]):
    time.sleep(PACKET_DELAY)
    response = send(plain)
    success = "\"r\":0" in response
    if success:
        r = CNNetwork.decrypt(response)
        return success, json.loads(r)["e"]["d"]
    else:
        r = CNNetwork.decrypt(response)
        print(r)
        return False, {}

def update_data_package(new_data: str = ""):
    """使用传入的new_data更新数据包，并永久保存到代码文件
    如果 new_data 为空，则跳过更新
    """
    global data_0
    new_data = new_data.strip()
    if not new_data:
        return False

    data_0 = new_data

    try:
        script_path = __file__
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()

        import re
        # 假设原文件中有 data_0 的定义格式为：data_0 = '''q<旧数据>'''
        pattern = r"data_0\s*=\s*'''q.*?'''"
        new_data_0_def = f"data_0 = '''q{new_data}'''"
        new_content = re.sub(pattern, new_data_0_def, content, flags=re.DOTALL)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print("数据包已更新成功！")
        return True

    except Exception as e:
        print(f"警告: 无法永久保存到文件: {e}")
        print("数据包已在本次运行中更新，但重启后需要重新输入")
        return False

def make_sk_uk():
    global pi, sk, ui, uk, data_0
    max_retries = 3  # 最大重试次数

    for attempt in range(max_retries):
        try:
            decrypted_data = CNNetwork.decrypt(data_0)  # 假设这个方法能够处理data_0并返回解密后的JSON字符串
            res = json.loads(decrypted_data)  # 尝试加载解密后的JSON字符串
        except json.JSONDecodeError as e:
            os.system('clear')
            print(f" 解密后的数据不是有效的JSON: {e}")
            print("请检查您填写的数据包是否正确")
            
            if attempt < max_retries - 1:  # 不是最后一次尝试
                if update_data_package():
                    continue
                else:
                    break
            else:
                # 尝试使用账号密码登录
                print("\n数据包解析失败，尝试使用账号密码登录...")
                if check_package_expiry_and_login():
                    return
               
        except Exception as e:
            os.system('clear')
            print(" 本地加解密处理失败，请检查数据包格式")
            print(f"错误详情: {e}")
            
            if attempt < max_retries - 1:  # 不是最后一次尝试
                if update_data_package():
                    continue
                else:
                    break
            else:
                # 尝试使用账号密码登录
                print("\n加解密失败，尝试使用账号密码登录...")
                if check_package_expiry_and_login():
                    return
                return

        # 如果解密成功，提取基本信息
        try:
            pi = res["e"]["pi"]
            sk = res["e"]["sk"] 
            ui = res["e"]["ui"]
            print(f"成功提取账号信息: UI={ui}")
            break  # 成功后跳出循环
        except KeyError as e:
            print(f" 数据包中缺少必要字段: {e}")
            if attempt < max_retries - 1:
                if update_data_package():
                    continue
                else:
                    break
            else:
                # 尝试使用账号密码登录
                print("\n数据包字段缺失，尝试使用账号密码登录...")
                if check_package_expiry_and_login():
                    return
                return
    else:
        print("已达到最大重试次数，无法获取有效的账号信息")
        # 尝试使用账号密码登录
        print("\n所有尝试失败，尝试使用账号密码登录...")
        if check_package_expiry_and_login():
            return
        return

    # 尝试获取uk值
    try:
        data_V316 = {"req": "V316", "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        _, res = send_加密发送_解密响应(data_V316)
    except RuntimeError:
        print("获取uk时发生未知错误")
        
    if res:
        uk = int(res["p"]["uk"])
        print(f"成功获取完整账号信息: PI={pi}, UK={uk}")
    else:
        print("\n" + "="*60)
        print("抓的包已过期，请重新抓包填进去")
        
        # 调用已有的数据包检查和登录逻辑，重新更新数据包并重新解析
        if check_package_expiry_and_login():
            try:
                # 重新解析更新后的数据包
                decrypted_data = CNNetwork.decrypt(data_0)
                res = json.loads(decrypted_data)
                pi = res["e"]["pi"]
                sk = res["e"]["sk"] 
                ui = res["e"]["ui"]
            except Exception as e:
                print(f"解析更新后的数据包失败: {e}")
                return
            
            try:
                data_V316 = {"req": "V316", "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                _, res = send_加密发送_解密响应(data_V316)
                if res:
                    uk = int(res["p"]["uk"])
                    print(f"成功获取完整账号信息: PI={pi}, UK={uk}")
            except:
                print("警告: 无法获取uk值，可能影响部分功能")
            return
        
        # 如果check_package_expiry_and_login失败，则尝试使用传统的update_data_package
        if update_data_package():
            print("使用新数据包重新尝试...")
            # 重新解析更新后的数据包
            try:
                decrypted_data = CNNetwork.decrypt(data_0)
                res = json.loads(decrypted_data)
                pi = res["e"]["pi"]
                sk = res["e"]["sk"] 
                ui = res["e"]["ui"]
                
                data_V316 = {"req": "V316", "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                _, res = send_加密发送_解密响应(data_V316)
                if res:
                    uk = int(res["p"]["uk"])
                    print(f"成功获取完整账号信息: PI={pi}, UK={uk}")
                else:
                    print("新数据包仍然无效")
            except Exception as e:
                print(f"解析更新后的数据包失败: {e}")
        else:
            return
def make_刷新(d_刷新,刷新次数,成功次数):
  for i in range(3):
    
    代码={'防风草':200018,'芦笋战机':1191,'大力花菜碎片':1162,'牛肝菌碎片':22000590,'祝福券':23123,'原始坚果碎片':111136,'凤仙花射手碎片':22000310,'金币':4013,'爆炸坚果碎片':111153,'冰仙子碎片':111162,'防风草碎片':22000180,'夜影龙葵碎片':111154,'钻石':3008,'三重射手碎片':1130,'三重射手':1030,'爆炸坚果':111053}
    suc,r=send_发送_解密响应(d_刷新)  
    if not suc:
        continue
    r_代码=int(r['fl'][0]['i'])
    if suc:
     for key, value in 代码.items():
      if value == int(r_代码):
        if key =='祝福券' :
            r_数量=r['fl'][0]['q']
            print(f'刷新成功，恭喜🎉🎉获得{key} {r_数量}个')
            return "成功"
        elif key =="钻石":
            r_数量=r['fl'][0]['q']
            if r_数量>10:
               print(f'刷新成功，恭喜🎉🎉获得{key} {r_数量}个')
               return "成功"
            else:
                print(f'刷新成功，只获得{key} {r_数量}个,太少了不要')
                return "不要"
        else:
           print(f"刷新第{刷新次数}次，已成功{成功次数}次,获得{key}{r['fl'][0]['q']}个,再次尝试")
           return "不要"
    # 如果循环结束都没有找到，可以打印一个未找到的消息
     input(f"发现一个未知奖励，请回游戏确认,植物代码{r['fl'][0]['i']}")
     return "未知"
  print("刷新失败")
  return "失败"
  
def make_时空寻宝主程序():
    d_刷新={"req":"V986","e":{"ai":"0","pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
    d_刷新=CNNetwork.encrypt_dict(d_刷新)                          
    c_设定=int(input("请输入成功几次后停止:"))
    count = 0
    刷新次数=0
    while True:
        刷新次数+=1
        r=make_刷新(d_刷新,刷新次数,count)
        if r =='成功':
            d={"req":"V986","e":{"ai":"0","pi":pi,"sk":sk,"t":"0","ui":ui},"ev":1}
            suc,r=send_加密发送_拼接提示(d,"获取奖励")       
            count=count+1 if suc else count
            
            if count >= c_设定:
                input(f"恭喜任务完成🎉🎉，已经成功{count}次")
                return
        elif r=='失败':
            d={"req":"V984","e":{"pi":pi,"sk":sk,"ui":ui,"wn":"3"},"ev":1}
            suc,r=send_加密发送_解密响应(d)
            r_代码=int(r['fl'][0]['i'])
            代码={'防风草':200018,'芦笋战机':1191,'大力花菜碎片':1162,'牛肝菌碎片':22000590,'祝福券':23123,'原始坚果碎片':111136,'凤仙花射手碎片':22000310,'金币':4013,'爆炸坚果碎片':111153,'冰仙子碎片':111162,'防风草碎片':22000180,'夜影龙葵碎片':111154,'钻石':3008,'三重射手碎片':1130,'三重射手':1030,'爆炸坚果':111053}
            if suc:
              for key, value in 代码.items():
                if value == int(r_代码):
                  if key =='祝福券':
                    r_数量=r['fl'][0]['q']
                    print(f'刷新成功，恭喜🎉🎉获得{key} {r_数量}个')
                    d={"req":"V986","e":{"ai":"0","pi":pi,"sk":sk,"t":"0","ui":ui},"ev":1}
                    suc,r=send_加密发送_拼接提示(d,"获取奖励")       
                    count=count+1 if suc else count
                    if count >= c_设定:
                       input(f"恭喜任务完成🎉🎉，已经成功{count}次")
                       return
                  else:
                     print(f"刷新成功，获得{key}{r['fl'][0]['q']}个,再次尝试")
        elif r=='未知':
            return

make_sk_uk()

def make_追击700钻():
    for i in range(0, 3):
        request = {"req": "V965", "e": {"is": str(i), "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(request, "领取{}钻石".format(2 ** i * 100))


def make_查询追击分数():
    data_query_pursuit = {"req": "V303",
                          "e": {"al": [{"id": 10800, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                                "pack": "", "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    r = send_加密发送_解密响应(data_query_pursuit)
    try:
        r_0 = json.loads(r[1][0]["data"])
        r_总分 = int(r_0['s'])
        r_电池 = int(r_0['f'])
        print(f"目前追击总分为{r_总分}分")
        r_data = {"总分": r_总分, "电池": r_电池}
        # print(r_data)
        return r_data
    except RuntimeError:
        print("查询追击分数失败")


def make_追击游玩(d_关卡数, d_辣椒, d_分数, t_0):
    data_pursuit_play = {"req": "V927",
                         "e": {"fr": {"t": t_0, "l": d_关卡数, "g": d_辣椒, "s": d_分数, "r": "1", "b": t_0}, "g": "1",
                               "on": "ef647c8f138b4c8fae810004c3e40173", "pi": pi, "pr": {
                                 "pl": [{"i": 111035, "q": 3}, {"i": 111029, "q": 3}, {"i": 1001, "q": 3},
                                        {"i": 1003, "q": 3}, {"i": 1002, "q": 3}, {"i": 1024, "q": 3}]}, "sk": sk,
                               "ui": ui}, "ev": 1}
    data_普通_boss = {1: "普通关", 2: "boss关"}
    # t_0 = 1为普通关，2为boss关
    send_加密发送_拼接提示(data_pursuit_play, f"发送{data_普通_boss[t_0]}第{d_关卡数}关, 第{d_辣椒}难度，{d_分数}分")


def make_追击14w分_700钻():
    f_0 = make_查询追击分数()
    if f_0['总分'] < 5000:
        make_免费电池()
        f_0 = make_查询追击分数()
        if f_0['电池'] < 25:
            input("电池不足25, 请确定有25电池再使用本函数")
            return
        make_追击游玩(1, 3, 16014, 1)  # 第1关, 第3难度, 16014分, 普通关
        make_追击游玩(2, 3, 16014, 1)
        make_追击游玩(3, 3, 16014, 1)
        make_追击游玩(4, 3, 16014, 1)
        make_追击游玩(5, 2, 22108, 1)
        make_追击游玩(1, 1, 18015, 2)  # 第1关, 第1难度, 18015,boss关
        make_追击游玩(2, 2, 18015, 2)
        make_追击游玩(3, 3, 18015, 2)
        make_追击700钻()
    elif f_0['总分'] < 140000:
        make_免费电池()
        f_0 = make_查询追击分数()
        if f_0['电池'] < 25:
            input("电池不足25, 请确定有25电池再使用本函数")
            return

        l_总 = [(1, 3, 16014, 1), (2, 3, 16014, 1), (3, 3, 16014, 1), (4, 3, 16014, 1), (5, 2, 22108, 1),
                (1, 1, 18015, 2), (2, 2, 18015, 2), (3, 3, 18015, 2)]
        for l_0 in l_总:
            make_追击游玩(l_0[0], l_0[1], l_0[2], l_0[3])
            f_0 = make_查询追击分数()
            if f_0['总分'] >= 140000:
                make_追击700钻()
                return
        input("700钻领取失败, 请确认boss关可打再运行本函数")
    else:
        make_追击700钻()


def make_追击每日():
    make_进入追击()
    make_免费电池()
    f_0 = make_查询追击分数()
    if f_0['电池'] < 20:
        print("电池不足20, 请确定有20电池再使用本函数")
        return
    for i in range(1, 5):  # 第1-4关, 第3难度, 0分, 普通关
        make_追击游玩(i, 3, 0, 1)
    for i in range(1, 4):  # 第1-3关, 第1-3难度, 0分, boss关
        make_追击游玩(i, i, 0, 2)

def make_十月同游日常():
    for i in range(1,12):
        d={"req":"V1053","e":{"k":str(i - 1),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(d,"十月同游每日第{}个".format(i))
    
def make_十月同游每月():
    for i in range(1,12):
        d={"req":"V1053","e":{"k":str(i - 1),"pi":pi,"sk":sk,"t":"3","ui":ui},"ev":1}
        send_加密发送_拼接提示(d,"十月同游每月第{}个".format(i))

def make_十月同游个人():
    for i in range(1,5):
        d={"req":"V1053","e":{"k":str(i - 1),"pi":pi,"sk":sk,"t":"4","ui":ui},"ev":1}
        send_加密发送_拼接提示(d,"十月同游个人任务第{}个".format(i))

def make_追击每周():
    make_免费电池()
    f_0 = make_查询追击分数()
    if f_0['电池'] < 70:
        input("电池不足70, 请确定有70电池再使用本函数")
        return
    for i in range(1, 6):  # 第1-5关, 第1难度, 0分, 普通关
        make_追击游玩(i, 1, 0, 1)

    for i in range(1, 5):  # 第1-4关, 第2难度, 0分, 普通关
        make_追击游玩(i, 2, 0, 1)

    make_追击游玩(5, 2, 22012, 1)  # 第五关,2难度,22012分,普通关

    for i in range(1, 5):  # 第1-4关, 第3难度,16015分, 普通关
        make_追击游玩(i, 3, 16015, 1)

    for i in range(1, 4):  # 第1-3关, 第1-3难度,18063分, BOSS关
        make_追击游玩(i, i, 18063, 2)
    f_0 = make_查询追击分数()
    if f_0['总分'] >= 140000:
        make_追击700钻()
        return
    input("分数没有达到14万分，可能是boss不在家或者网络问题发送失败")


def make_每日领钻石装扮券():
    d = {"req": "V766", "e": {"id": "1", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(d, "分享庭院关卡获得10钻石")
    for i in range(1, 6):
        data = {"req": "V765", "e": {"id": "1", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "第{}次领取10钻石".format(i))
    for i in range(1, 4):
        data = {"req": "V765", "e": {"id": "23", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "第{}次领取2装扮券".format(i))
    d_抽奖 = {"req": "V303", "e": {"al": [{"id": 10615, "abi": 0, "type": 1, "config_version": 1}],
                                   "ci": "81", "cs": "0", "pack": "com.popcap.pvz2cthd360",
                                   "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    send_加密发送_拼接提示(d_抽奖, "点击抽奖")
    
    fail_count = 0 
    total_rewards = {}

    for i in range(1, 41):
        data = {"req": "V940", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        suc, r = send_加密发送_解密响应(data)
        print("第{}/40次抽奖".format(i), "成功" if suc else "失败")
        if not suc:
            fail_count += 1
            if fail_count == 2:
                print("连续失败2次，终止抽奖")
                break
        else:
            fail_count = 0 
            try:
                bl_field = r['bl']
            except KeyError as e:
                print("奖励字段解析失败，无法读取奖励信息：", e)
            else:
                print("获得奖励：")
                for item in bl_field:
                    code = str(item['i'])
                    qty = item.get('q', 0)
                    if code in 道具字典:
                        reward_name = 道具字典[code]
                    elif code in 植物碎片字典:
                        reward_name = 植物碎片字典[code]
                    elif code in 植物装扮碎片字典:
                        reward_name = 植物装扮碎片字典[code]
                    else:
                        reward_name = code  
                    print(f"{reward_name} x {qty}")
                    total_rewards[reward_name] = total_rewards.get(reward_name, 0) + qty

    print("抽奖操作结束")
    print("本次累计获得奖励：")
    if total_rewards:
        for reward, total_qty in total_rewards.items():
            print(f"{reward} x {total_qty}")
    else:
        print("未获得任何奖励")



def make_七日指南():
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(1000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第一天第{}个".format(i))
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(2000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第二天第{}个".format(i))
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(3000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第三天第{}个".format(i))
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(4000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第四天第{}个".format(i))
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(5000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第五天第{}个".format(i))
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(6000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第六天第{}个".format(i))
    for i in range(1, 8):
        data = {"req":"V951","e":{"ai":"10828","i":str(7000 + i),"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "七日指南第七天第{}个".format(i))



def make_潘妮课堂():
    for i in range(1, 6):
        data = {"req":"V760","e":{"i":str(i - 1),"pi":pi,"s":"0","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "潘妮课堂1第{}个".format(i))
    for i in range(1, 6):
        data = {"req":"V760","e":{"i":str(i - 1),"pi":pi,"s":"1","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "潘妮课堂2第{}个".format(i))
    for i in range(1, 6):
        data = {"req":"V760","e":{"i":str(i - 1),"pi":pi,"s":"2","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "潘妮课堂3第{}个".format(i))
    for i in range(1, 6):
        data = {"req":"V760","e":{"i":str(i - 1),"pi":pi,"s":"3","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "潘妮课堂4第{}个".format(i))



def make_潘妮课堂买植物():
    for i in range(1, 14):
        data = {"req":"V392","e":{"ci":"1","gi":"111138","mi":"23405","pi":pi,"q":"1","si":"12","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "第{}次购买原始向日葵碎片".format(i))
    for i in range(1, 14):
        data = {"req":"V392","e":{"ci":"1","gi":"1199","mi":"23405","pi":pi,"q":"1","si":"12","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "第{}次购买蓝莓碎片".format(i))
    for i in range(1, 14):
        data = {"req":"V392","e":{"ci":"1","gi":"1129","mi":"23405","pi":pi,"q":"1","si":"12","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "第{}次购买高坚果碎片".format(i))
    for i in range(1, 14):
        data = {"req":"V392","e":{"ci":"1","gi":"1170","mi":"23405","pi":pi,"q":"1","si":"12","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "第{}次购买大嘴花碎片".format(i))
    for i in range(1, 14):
        data = {"req":"V392","e":{"ci":"1","gi":"1114","mi":"23405","pi":pi,"q":"1","si":"12","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "第{}次购买窝瓜碎片".format(i))



def make_七日指南奖励():
    x = 0  # 初始化成功次数
    for i in range(1, 29):
        data = {"req":"V951","e":{"ai":"10828","i":str(i - 1),"pi":pi,"sk":sk,"t":"2","ui":ui},"ev":1}
        suc, r = send_加密发送(data)
        if suc:
            x += 1
            print("发送第{}次, 已领取七日指南奖励".format(i))
            if x == 7:
                print("七日指南奖励领取完毕")
                return
        else:
            print("七日指南奖励领取失败")

def make_七天签到():
    data_七日签到 = {"req":"V350","e":{"ai":"10710","pi":pi,"sk":sk,"ui":ui},"ev":1}
    send_加密发送_拼接提示(data_七日签到,"七日签到成功")

def make_砸罐任务():
    x = 0  # 初始化成功次数
    data_砸罐任务获取 = {"req": "V303",
                         "e": {"al": [{"id": 10790, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                               "pack": "com.popcap.pvz2cthd4399", "pi": pi, "sk": sk, "ui": ui, "v": newest_version},
                         "ev": 1}
    suc, r = send_加密发送_解密响应(data_砸罐任务获取)
    try:
        r = json.loads(r[0]["data"])['ftl']
    except (json.JSONDecodeError, KeyError):
        print("砸罐任务列表获取失败，可能是活动已结束")
        return
    for i in r:
        data = {"req": "V920", "e": {"i": i, "pi": pi, "sk": sk, "t": "1", "ui": ui}, "ev": 1}
        suc, _ = send_加密发送_拼接提示(data, f"领取砸罐任务{i}")
        if suc:
            x += 1

    print(f"砸罐任务完成，共成功领取 {x} 个任务")



def make_双人每日每周():
    data_点击双人 = {"req": "V303",
                     "e": {"al": [{"id": 10859, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                           "pack": "com.popcap.pvz2cthd4399", "pi": pi, "sk": sk, "ui": ui, "v": newest_version},
                     "ev": 1}
    send_加密发送_解密响应(data_点击双人)
    data_获取双人任务 = {"req": "V303",
                         "e": {"al": [{"id": 10861, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                               "pack": "com.popcap.pvz2cthd4399", "pi": pi, "sk": sk, "ui": ui, "v": newest_version},
                         "ev": 1}
    suc, r = send_加密发送_解密响应(data_获取双人任务)
    try:
        data_日常任务列表 = json.loads(r[0]['data'])['day_task_list']
    except (json.JSONDecodeError, KeyError):
        print("双人任务列表获取失败，可能是赛季已结束")
        return
    data_周任务列表 = json.loads(r[0]['data'])['week_task_list']

    daily_success_count = 0
    for key, value in data_日常任务列表.items():
        if value == 0:
            data_日常任务 = {
                "req": "V857",
                "e": {
                    "pi": pi,
                    "sk": sk,
                    "ti": key,
                    "type": "0",
                    "ui": ui,
                    "wi": "0"
                },
                "ev": 1
            }
            suc, resp = send_加密发送_解密响应(data_日常任务)
            if suc:
                daily_success_count += 1
                try:
                    bl_field = resp['bl']
                except (KeyError, TypeError) as e:
                    print("错误：任务奖励字段（bl）缺失", e)
                    continue
                print(f"日常任务[ti={key}]领取奖励：")
                for item in bl_field:
                    code = str(item.get('i', ''))
                    qty = item.get('q', 0)
                    if not code:
                        continue
                    if code in 双人对决僵尸字典:
                        reward_name = 双人对决僵尸字典[code]
                        if code in ["404065", "404011", "404025", "404030", "404035",
                                    "404040", "404045", "404050", "404055", "404060"]:
                            reward_name = Fore.LIGHTYELLOW_EX + reward_name + Style.RESET_ALL
                    elif code in 道具字典:
                        reward_name = 道具字典[code]
                    else:
                        reward_name = code  
                    print(f"  {reward_name} x {qty}")
            else:
                print(f"日常任务[ti={key}]领取失败，请再次尝试")
    print(f"双人每日任务已完成，共领取 {daily_success_count} 次")
    make_双人领取()
    if daily_success_count == 0:
        return
    for d in data_周任务列表:
        for key, value in d.items():
            if value == 0:
                week = (int(key) - 2001) // 5 + 1
                attempt = (int(key) - 2001) % 5 + 1
                data_周任务 = {
                    "req": "V857",
                    "e": {
                        "pi": pi,
                        "sk": sk,
                        "ti": key,
                        "type": "1",
                        "ui": ui,
                        "wi": str(week)
                    },
                    "ev": 1
                }
                suc, resp = send_加密发送_解密响应(data_周任务)
                print(f"双人第{week}周第{attempt}次任务", "成功" if suc else "失败")
                if suc:
                    try:
                        weekly_bl_field = resp['bl']
                    except (KeyError, TypeError) as e:
                        print("错误：每周奖励字段（bl）缺失或解析失败", e)
                        continue
                    print("获得每周奖励：")
                    for item in weekly_bl_field:
                        code = str(item.get('i', ''))
                        qty = item.get('q', 0)
                        if not code:
                            continue
                        if code in 双人对决僵尸字典:
                            reward_name = 双人对决僵尸字典[code]
                            if code in ["404065", "404011", "404025", "404030", "404035",
                                        "404040", "404045", "404050", "404055", "404060"]:
                                reward_name = Fore.LIGHTYELLOW_EX + reward_name + Style.RESET_ALL
                        elif code in 道具字典:
                            reward_name = 道具字典[code]
                        else:
                            reward_name = code
                        print(f"  {reward_name} x {qty}")
    print("双人周任务已完成")
    make_双人领取()


def make_周回忆普通关():
    for i in range(1, 10):
        data = {"req": "V971",
                "e": {"gl": str(i - 1), "pi": pi, "r": "2", "sk": sk, "tgt": "0,1,2", "tp": "1", "ui": ui, "wi": "1"},
                "ev": 1}
        send_加密发送_拼接提示(data, "通过回忆普通第{}关".format(i))


def make_回忆困难():
    for i in range(1, 18):
        data = {"req": "V971",
                "e": {"gl": str(i - 1), "pi": pi, "r": "2", "sk": sk, "tgt": "0,1,2", "tp": "2", "ui": ui, "wi": "1"},
                "ev": 1}
        send_加密发送_拼接提示(data, "通过回忆困难第{}关".format(i))

def make_回忆之旅商店():
    data = {"req": "V972",
            "e": {"c": "0", "pi": pi, "s": "0", "sk": sk, "ui": ui}, 
            "ev": 1}
    
    suc, r = send_加密发送_解密响应(data)
    if not suc:
        print("获取商店数据失败")
        return
        
    try:
        shop_list = r['shopList'] 
        user_money = int(r.get('userMoney', 0))  
        user_super_money = int(r.get('userSuperMoney', 0)) 
        
        print("\n当前商店可购买物品:")
        print("=" * 60)
        
        for i, item in enumerate(shop_list, 1):
            item_id = str(item['i'])
            quantity = item['q'] 
            max_buy = item['m']
            price = item['c']
            currency_id = str(item['t'])
            already_bought = item.get('f', 0) 
            own_status = item.get('own', 0) 
            
            if item_id in 植物碎片字典:
                item_name = 植物碎片字典[item_id] 
            elif item_id in 道具字典:
                item_name = 道具字典[item_id]
            elif item_id in 神器字典:
                item_name = 神器字典[item_id]
            elif item_id in 植物装扮碎片字典:
                item_name = 植物装扮碎片字典[item_id]
            else:
                item_name = f"未知物品({item_id})"
                
            currency_name = 道具字典.get(currency_id, f"未知货币({currency_id})")
            
            if item_id in 神器字典 and own_status == 1:
                print(f"{i}. {LIGHTCYAN}{item_name}{RESET} --- {LIGHTRED}神器已拥有{RESET}")
            else:
                remaining_buys = max_buy - already_bought
                print(f"{i}. {LIGHTCYAN}{item_name}{RESET}-------数量:{YELLOW}{quantity}{RESET}-------限购{LIGHTCYAN}{remaining_buys}{RESET}/{LIGHTGREEN}{max_buy}{RESET}次-------{LIGHTMAGENTA}{price}{RESET}{currency_name}")
            
        print("=" * 60)
        print(f"{YELLOW}黄色蜗牛币: {user_money}{RESET}")
        print(f"{LIGHTMAGENTA}彩色蜗牛币: {user_super_money}{RESET}")
        
        while True:
            choice = input("\n请选择要购买的物品编号(输入0退出): ")
            if choice == "0":
                break
                
            try:
                index = int(choice) - 1
                if 0 <= index < len(shop_list):
                    selected_item = shop_list[index]
                    item_id = str(selected_item['i'])
                    max_buy = selected_item['m']
                    price = selected_item['c']
                    currency_id = str(selected_item['t'])
                    already_bought = selected_item.get('f', 0)
                    remaining_buys = max_buy - already_bought
                    own_status = selected_item.get('own', 0)
                    
                    if item_id in 神器字典 and own_status == 1:
                        print(f"\n{LIGHTRED}您已拥有该神器，无法购买{RESET}")
                        continue
                    
                    if item_id in 植物碎片字典:
                        item_name = 植物碎片字典[item_id] 
                    elif item_id in 道具字典:
                        item_name = 道具字典[item_id]
                    elif item_id in 神器字典:
                        item_name = 神器字典[item_id]
                    elif item_id in 植物装扮碎片字典:
                        item_name = 植物装扮碎片字典[item_id]
                    else:
                        item_name = f"未知物品({item_id})"
                    
                    print(f"\n已选择: {LIGHTCYAN}{item_name}{RESET}, 每个价格: {LIGHTMAGENTA}{price}{RESET}")
                    if currency_id == "23400": 
                        max_affordable = user_money // price
                    elif currency_id == "23401": 
                        max_affordable = user_super_money // price
                    else:
                        max_affordable = 9999  
                    
                    max_possible = min(remaining_buys, max_affordable)
                    
                    if remaining_buys <= 0:
                        print(f"{RED}该物品已达到购买上限，无法继续购买{RESET}")
                        continue
                    buy_count = input(f"请输入购买数量(限购{LIGHTYELLOW}{max_buy}{RESET}次，还能购买{LIGHTGREEN}{remaining_buys}{RESET}次):")
                    try:
                        buy_count = int(buy_count)
                        if buy_count <= 0:
                            print("购买数量必须大于0")
                            continue
                        
                        if buy_count > remaining_buys:
                            print(f"超出可购买次数，最多还能购买{remaining_buys}次")
                            continue
                            
                        if (currency_id == "23400" and buy_count * price > user_money) or \
                           (currency_id == "23401" and buy_count * price > user_super_money):
                            print("蜗牛币不足")
                            continue
                        
                        successful_purchases = 0
                        for i in range(buy_count):
                            purchase_data = {
                                "req": "V392",
                                "e": {
                                    "ci": price,
                                    "gi": item_id,
                                    "mi": currency_id,
                                    "pi": pi,
                                    "q": "1", #别改这个会吞币
                                    "si": 10,
                                    "sk": sk,
                                    "ui": ui
                                },
                                "ev": 1
                            }
                            
                            suc, purchase_result = send_加密发送_拼接提示(purchase_data, f"购买{item_name} 第{i+1}/{buy_count}次")
                            
                            if suc:
                                successful_purchases += 1
                                if currency_id == "23400": 
                                    user_money -= price
                                elif currency_id == "23401":  
                                    user_super_money -= price
                            else:
                                print(f"{RED}第{i+1}次购买失败！{RESET}")
                                break
                        
                        if successful_purchases > 0:
                            print(f"{GREEN}成功购买了 {successful_purchases} 个 {item_name}！{RESET}")
                            print(f"{YELLOW}剩余黄色蜗牛币: {user_money}{RESET}")
                            print(f"{LIGHTMAGENTA}剩余彩色蜗牛币: {user_super_money}{RESET}")
                        else:
                            print(f"{RED}所有购买均失败！{RESET}")
                            
                    except ValueError:
                        print("请输入有效的数字")
                else:
                    print("无效的物品编号")
            except ValueError:
                print("请输入有效的数字")
            
    except KeyError as e:
        print(f"解析商店数据失败: {e}")
        





def make_童话森林第一章普通():
    for i in range(1, 8):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "", "type": "0", "ui": ui, "win": "1",
                      "world": "uncharted_tale"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过童话森林第一章普通第{}关".format(i))
def make_童话森林第一章困难():
    for i in range(1, 8):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "1,1,1", "type": "1", "ui": ui, "win": "1",
                      "world": "uncharted_tale"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过童话森林第一章困难第{}关".format(i))
def make_童话森林第二章普通():
    for i in range(1, 9):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "", "type": "0", "ui": ui, "win": "1",
                      "world": "uncharted_tale_2"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过童话森林第二章普通第{}关".format(i))
def make_童话森林第二章困难():
    for i in range(1, 9):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "1,1,1", "type": "1", "ui": ui, "win": "1",
                      "world": "uncharted_tale_2"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过童话森林第二章困难第{}关".format(i))


def make_免费电池():
    for i in range(1, 3):
        data = {"req": "V765", "e": {"id": "5", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "免费领取5电池第{}次".format(i))


def make_一键宗师():
    try:
        data = {"req": "V303", "e": {"al": [{"id": 10859, "abi": 0, "type": 1, "config_version": 1}], "ci": "93", "cs": "0", "pack": 渠道, "pi":pi, "sk": sk, "ui":ui, "v": newest_version}, "ev": 1}
        suc, r = send_加密发送_解密响应(data)
        if not suc or not r or not isinstance(r, list) or 'data' not in r[0]:
            print("段位请求失败或响应格式错误")
            return
        try:
            data_str = r[0]['data']
            data_dict = json.loads(data_str)
            grade = data_dict['pf']['grade']
            big = grade['big']
            small = grade['small']
            star = grade['star']
        except Exception as e:
            print(f"解析段位数据失败: {e}")
            return

        big_rank_mapping = {0: "铜锅", 1: "银锅", 2: "金锅", 3: "钻锅", 4: "大师锅", 5: "宗师锅"}
        small_rank_mapping = {0: "V", 1: "IV", 2: "III", 3: "II", 4: "I"}
        big_rank = big_rank_mapping.get(big, str(big))
        small_rank = small_rank_mapping.get(small, str(small))
        print(f"当前段位：{big_rank}{small_rank}  {star}星")
        result = 100 - big * 20 - small * 5 - star
        if result < 1:
            print("已达到满星宗师")
            return
        print(f"需要循环发送 {result} 次一键宗师包请求")
        for i in range(1, result + 1):
            try:
                data_v826 = {"req": "V826", "e": {"bot": "1", "botTimes": "1", "pi": pi, "sk": sk, "ui": ui, "win": "1"}, "ev": 1}
                send_加密发送_拼接提示(data_v826, f"发送一键宗师包第{i}/{result}次")
            except Exception as inner_e:
                print(f"发送第{i}次请求时出错: {inner_e}")
                continue
    except Exception as e:
        print(f"发生异常: {e}")



colors = ["\033[94m", "\033[91m", "\033[0m", "\033[38;5;202m", "\033[35m", "\033[94m", "\033[32m", "\033[97m", "\033[93m", "\033[96m"]

def get_random_color():
    return random.choice(colors)

def make_碎片挑战():
    print("\033[91m=======================《碎片挑战》======================\033[0m")
    YELLOW = "\033[33m"
    WHITE = "\033[37m"
    GREEN = "\033[32m"
    CYAN = "\033[36m" 
    PURPLE = "\033[35m"
    ORANGE = "\033[38;5;208m"
    RESET = "\033[0m"

    plants = {
        "1": {"name": f"{ORANGE}仙人掌{RESET}", "id": 111129},
        "2": {"name": f"{PURPLE}蚕豆突击队{RESET}", "id": 1193},
        "3": {"name": f"{PURPLE}椰子加农炮{RESET}", "id": 1123},
        "4": {"name": f"{PURPLE}烈焰菇{RESET}", "id": 1159},
        "5": {"name": f"{PURPLE}蒲公英{RESET}", "id": 1161},
        "6": {"name": f"{CYAN}激光豆{RESET}", "id": 1139},
        "7": {"name": f"{CYAN}南瓜巫师{RESET}", "id": 111104},
        "8": {"name": f"{CYAN}魔音甜菜{RESET}", "id": 111123},
        "9": {"name": f"{CYAN}窝瓜{RESET}", "id": 1114},
        "10": {"name": f"{CYAN}潜伏芹菜{RESET}", "id": 111125},
        "11": {"name": f"{CYAN}双胞向日葵{RESET}", "id": 1108},
        "12": {"name": f"{CYAN}星星果{RESET}", "id": 1140},
        "13": {"name": f"{CYAN}橡木弓手{RESET}", "id": 1160},
        "14": {"name": f"{CYAN}辣椒投手{RESET}", "id": 1180},
        "15": {"name": f"{CYAN}火龙果{RESET}", "id": 111118},
        "16": {"name": f"{CYAN}原始向日葵{RESET}", "id": 111138},
        "17": {"name": f"{CYAN}孢子菇{RESET}", "id": 111126},
        "18": {"name": f"{CYAN}棉小雪{RESET}", "id": 111113},
        "19": {"name": f"{CYAN}莲小蓬{RESET}", "id": 1175},
        "20": {"name": f"{CYAN}鳄梨{RESET}", "id": 1168},
        "21": {"name": f"{CYAN}双重射手{RESET}", "id": 1127},
        "22": {"name": f"{GREEN}寒冰射手{RESET}", "id": 1119},
        "23": {"name": f"{GREEN}竹小弟{RESET}", "id": 1188},
        "24": {"name": f"{GREEN}复活萝卜{RESET}", "id": 111128},
        "25": {"name": f"{GREEN}棱镜草{RESET}", "id": 1137},
        "26": {"name": f"{GREEN}旋风橡果{RESET}", "id": 1185},
        "27": {"name": f"{GREEN}树脂投手{RESET}", "id": 1176},
        "28": {"name": f"{GREEN}回旋镖射手{RESET}", "id": 1107},
        "29": {"name": f"{GREEN}火炬树桩{RESET}", "id": 1120},
        "30": {"name": f"{GREEN}闪电芦苇{RESET}", "id": 1122},
        "31": {"name": f"{GREEN}西瓜投手{RESET}", "id": 1124},
        "32": {"name": f"{GREEN}钢地刺{RESET}", "id": 1128},
        "33": {"name": f"{GREEN}高坚果{RESET}", "id": 1129},
        "34": {"name": f"{GREEN}三重射手{RESET}", "id": 1130},
        "35": {"name": f"{GREEN}旋转菠萝{RESET}", "id": 1195},
        "36": {"name": f"{GREEN}眩晕洋葱{RESET}", "id": 1182},
        "37": {"name": f"{GREEN}大王花{RESET}", "id": 1184},
        "38": {"name": f"{GREEN}飞碟瓜{RESET}", "id": 1192},
        "39": {"name": f"{GREEN}漩涡枇杷{RESET}", "id": 1189},
        "40": {"name": f"{GREEN}香水蘑菇{RESET}", "id": 111137},
        "41": {"name": f"{GREEN}豌豆荚{RESET}", "id": 1125},
        "42": {"name": f"{WHITE}白萝卜{RESET}", "id": 1135},
        "43": {"name": f"{WHITE}小喷菇{RESET}", "id": 1149},
        "44": {"name": f"{WHITE}大丽菊{RESET}", "id": 111110},
        "45": {"name": f"{WHITE}竹笋{RESET}", "id": 1136},
        "46": {"name": f"{WHITE}地刺{RESET}", "id": 1111},
        "47": {"name": f"{WHITE}冰冻生菜{RESET}", "id": 1106},
        "48": {"name": f"{WHITE}卷心菜投手{RESET}", "id": 1105},
        "49": {"name": f"{WHITE}土豆地雷{RESET}", "id": 1104},
        "50": {"name": f"{WHITE}坚果{RESET}", "id": 1103},
        "51": {"name": f"{WHITE}向日葵{RESET}", "id": 1102},
        "52": {"name": f"{WHITE}豌豆射手{RESET}", "id": 1101}
    }
    print("请选择两种植物:")
    LEFT_WIDTH = 15
    plant_items = []
    for key in sorted(plants, key=lambda x: int(x)):
        plant_items.append((key, plants[key]["name"]))
    total = len(plant_items)
    for i in range(0, total, 3):
        line_parts = []
        for j in range(3):
            if i+j < total:
                key, name = plant_items[i+j]
                seq = f"{int(key):2d}. {name}"
                line_parts.append(ljust_visual(seq, LEFT_WIDTH))
            else:
                line_parts.append("")
        print("".join(line_parts))
    
    choice1 = input("请输入第一种植物: ").strip()
    choice2 = input("请输入第二种植物: ").strip()

    if choice1 not in plants or choice2 not in plants:
        print("无效的选择，请重新选择")
        return

    plant1 = plants[choice1]
    plant2 = plants[choice2]

    data_1 = {"req": "V299", "e": {"a": "2", "ad": "1", "ii": "10502", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}  # 巨人危机增加次数
    data_2 = {"req": "V798", "e": {"i": "10502", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}  # 巨人危机增加次数
    data_3 = {"req": "V299", "e": {"a": "2", "ad": "1", "ii": "10503", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}  # 邪恶入侵增加次数
    data_4 = {"req": "V798", "e": {"i": "10503", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}  # 邪恶入侵增加次数
    data_5 = {"req": "V299", "e": {"a": "1", "ad": "0", "ii": "10502",
                                   "ol": {str(plant1["id"]): 10, str(plant2["id"]): 10},
                                   "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    data_6 = {"req": "V299", "e": {"a": "1", "ad": "1", "ii": "10502",
                                   "ol": {str(plant1["id"]): 10, str(plant2["id"]): 10},
                                   "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    data_7 = {"req": "V299", "e": {"a": "1", "ad": "0", "ii": "10503",
                                   "ol": {str(plant1["id"]): 10, str(plant2["id"]): 10},
                                   "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    data_8 = {"req": "V299", "e": {"a": "1", "ad": "1", "ii": "10503",
                                   "ol": {str(plant1["id"]): 10, str(plant2["id"]): 10},
                                   "pi": pi, "sk": sk, "ui": ui}, "ev": 1}             
    data_9 = {"req": "V299", "e": {"a": "2", "ad": "1", "ii": "10501", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    data_10 = {"req": "V798", "e": {"i": "10501", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}              
    data_11 = {"req": "V299", "e": {"a": "1", "ad": "0", "ii": "10501",
                                    "ol": {str(plant1["id"]): 10, str(plant2["id"]): 10},
                                    "pi": pi, "sk": sk, "ui": ui}, "ev": 1}

    weekday = datetime.datetime.now().weekday()
    x = 0
    if weekday in [0, 2, 4, 5, 6]:
        suc, r = send_加密发送_拼接提示(data_5, "巨人危机第1次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_1, "巨人危机第1次增加次数")
        suc, r = send_加密发送_拼接提示(data_5, "巨人危机第2次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_2, "巨人危机第2次增加次数")
        suc, r = send_加密发送_拼接提示(data_5, "巨人危机第3次挑战")
        x = x + 1 if suc else x
        suc, r = send_加密发送_拼接提示(data_11, "暴走雪人第1次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_9, "暴走雪人第1次增加次数")
        suc, r = send_加密发送_拼接提示(data_11, "暴走雪人第2次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_10, "暴走雪人第2次增加次数")
        suc, r = send_加密发送_拼接提示(data_11, "暴走雪人第3次挑战")
        x = x + 1 if suc else x
        for i in range(1, 4):
            suc, r = send_加密发送_拼接提示(data_6, "巨人危机第{}次广告翻倍".format(i))
            x = x + 1 if suc else x

    if weekday in [1, 3, 4, 5, 6]:
        suc, r = send_加密发送_拼接提示(data_7, "邪恶入侵第1次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_3, "邪恶入侵第1次增加次数")
        suc, r = send_加密发送_拼接提示(data_7, "邪恶入侵第2次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_4, "邪恶入侵第2次增加次数")
        suc, r = send_加密发送_拼接提示(data_7, "邪恶入侵第3次挑战")
        x = x + 1 if suc else x
        suc, r = send_加密发送_拼接提示(data_11, "暴走雪人第1次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_9, "暴走雪人第1次增加次数")
        suc, r = send_加密发送_拼接提示(data_11, "暴走雪人第2次挑战")
        x = x + 1 if suc else x
        send_加密发送_拼接提示(data_10, "暴走雪人第2次增加次数")
        suc, r = send_加密发送_拼接提示(data_11, "暴走雪人第3次挑战")
        x = x + 1 if suc else x
        if weekday not in [4, 5, 6]:
            for i in range(1, 4):
                suc, r = send_加密发送_拼接提示(data_8, "邪恶入侵第{}次广告翻倍".format(i))
                x = x + 1 if suc else x
    print("碎片刷取完毕, 每种植物获得{}碎片".format(x * 10))


packets = [('753977724', '9a5ccab02d874a04b3057892c55a9f6f'), ('753977729', '725b371690644392b2bc5faad99d181f'),
           ('753977732', '0b1aefd7d9924ddf8071805d64225902'), ('753973723', 'e5466be14872431abe7592c9d953d951'),
           ('753973726', '0b84247e5858465e950d92b3f74d4950'), ('753973733', '44a9c913be354b4282381f0001100cfb'),
           ('753977751', '1a6ea6b5ea774a9ebe903bb680ba342d'), ('753977760', '158aa421cc0c4fa099eab34ee15ebf0d'),
           ('753973767', '898c2cf88f8943568016b65281f4b826'), ('753973769', '3094b0d8e86e4646ba9f588b0c936c2f'),
           ('753977762', 'c62115cdb40041ff873d634feb1b95dc'), ('753973936', '5b6ca64991bf48c38ec59632bf96d5b7'),
           ('753973938', '8a3a9ffd15c84ab293daf96f0a2f1ef7'), ('753973945', '558dfff4141d4964b40162b0846419c1'),
           ('753973947', '8a1abf4b29f04a3d8e4933e4b8a7f080'), ('753973966', '298b9a4f552a4af094b8f0e9195cf9e1'),
           ('753973984', '8c9a1940eedd4087a308d366ef58ad3a'), ('753973986', 'd7b85ef4cbbb4c51935d43291be1673d'),
           ('753973990', 'bacd02a8482343e881bb0b6beaf0bad0'), ('753973995', '6d7d709b531649bf97f00b535705e9a3'),
           ('753973998', 'a773904f886047f8a95d3b23526a84d8'), ('753974000', '68d0d6b3ed1a4c6ca1a66ab14e76fc56'),
           ('753974002', '5401cf8b4cb8408ba2ec789047e1e577'), ('753974004', '11caa698efd24257ac5c180662039af8'),
           ('753974006', '32db47e1654847aab5ea61ca592c1f17'), ('753974010', '6def103ee2f145b7a0804dc2cb0bc9ac'),
           ('753974013', 'caecce8c92744e20bef5deeab5332423'), ('753974014', 'ae67dc4f5d97497fa4f332bf268aecde'),
           ('753974024', '0ab6053e5ac1482faf8b82713a9ba1ee'), ('753974027', 'b08650fcd8024d86a0c3d84dcf850d10'),
           ('753974029', '9fc8aca386eb485d863048da5db16d74'), ('753974034', 'ad65206d9a474810954e87bb08796f71'),
           ('753974044', '5785f5bf86eb44e9b804677c13fa2431'), ('753974051', '1f5e5fecc5f4469fb3840b9dcf01d5dd'),
           ('753978042', '8410280066cb4a0488ab7f6ad999c12c'), ('753974070', 'f365c8a940344982a7ca8e9ab011af21'),
           ('753978067', '35ad8d87527e41f6bb463701b3fd7114'), ('753978072', '2d53732704bd4fe8a23d31939107cbd7'),
           ('753978087', 'fbee9f69b8794c838bf96c00d44fb599'), ('753974108', 'd77aee4624d841a8951b146c5c87ff1b'),
           ('753978094', 'af36b8606a7e41b38d3475b40721ad6b'), ('753974128', '7e131d21c2314252a8c19cb9abe6fc49'),
           ('753974130', 'c990dc12fb78429a99ece2e54a81124e'), ('753978117', 'cde1646bc98e4acf950c27a985a6dc27'),
           ('753978131', 'df0b8b3715d248e2862680dea03adec9'), ('753974166', '70b8c0e79a354aa986fdcd35b8fcb8d4'),
           ('753978148', 'a093c64d5be04bfdb73cc824f07985fc'), ('753978153', 'e02ec4fca81f466f91aaa214c022d99b'),
           ('753974202', '2f57df27e27b4e24be417bcf78518f65'), ('753974204', '3a7b199fd7974e97b87fef0140acb4d1'),
           ('753974206', 'e37472a74acd4c18a1c913cd6d131baf'), ('753974207', '0c6cb62d6ae64d3c8f1ac84ed26e7a2a'),
           ('753974221', 'b1bacce0b8534716ba8f1e07bf856065'), ('753974223', 'ae4e793b7c724fd8833f654e135fdf49'),
           ('753974225', '21409658a36446b59c1a5b6cccb132bb'), ('753974256', '892f425567b543ceaa850d142fdeceb7'),
           ('753974258', '9438c2a556b94d37b218ebd5af752489'), ('753974260', 'ff7fcb9475d442a7bc1989d34c24f885'),
           ('753974264', '9ec4b0cd9d534cfcac877cc705499c7e'), ('753974266', '9b3f3d8f1e124c89ba0ffc1dbed65bae'),
           ('753974268', '47dd3e41349a44dabbb7ef4659cad47c'), ('753974269', 'ac22384b4fc94436a6373915b890a757'),
           ('753974275', '3147282c9ba5475db569595b3852527d'), ('753974277', '48f7e8ea8ab445938b372a2b5c7d569e'),
           ('753974280', 'abaed72715a04a5fbba6b6818dbf1269'), ('753974282', 'f30d55178e2c44f1b78f3b9e9750e4c7'),
           ('753974284', '9f564102d6dc49328dda0a1ce7fae670'), ('753974288', 'b3daa8aba4a04343a3f8a5e5ad592d0d'),
           ('753974290', 'ac75d9adb0ef4c7f8136c6bc0c6fcde6'), ('753974294', '947fce1c64d04eed83722780c57b1b72'),
           ('753974299', '8ef9f1cd156b49af90d56001fa28d85e'), ('753974315', '35035e84ec6e4c769379f16b0ca80151'),
           ('753974321', '7cfcee0d7bbf445999966830d617e3dc'), ('753974325', '9901ef1437e748abaa48f3b254b23331'),
           ('753974328', '76a1f42f781644108f88c6bf5c4fd273'), ('753974329', '94eee07ff8734069816ebb3cf7c9b529'),
           ('753978360', '6d9b41e8212a4ffdbf1ac5457a99f687'), ('753974357', '2db6ff4ba6854542b46ec8354700bc38'),
           ('753974358', '4e3d5b22978b4519a88974230bae2aa6'), ('753974389', '84333a08543845438ea4a0edb44241df'),
           ('753974400', 'e3823b5218c34b1f9e3019cff65761bc'), ('753978392', '919c8fc160d846278503177cfb13101f'),
           ('753974410', '999cd5b25f954f44942de21f5e37339d'), ('753974425', '8e6824f35ea647ed9f0d375fdd3377f0'),
           ('753974431', 'f522ad9829fa4d79859b7f640bcbdfd7'), ('753974434', 'cfdfcea11ffa4b59be6f37794a617e6c'),
           ('753974438', 'febb385d67954d2e9c69889b7897fd22'), ('753974439', '66efcee5f48842608e154ba16779d5d7'),
           ('753974440', 'aa834a1b50ed40bf92e9819270bd9857'), ('753974442', '5d33451b88504e4f9e11177735d1d2b3'),
           ('753974446', '71294224049241ea9dcd8f22fe2bd7e3'), ('753974454', 'ca12bb78c136450187ee5d6d6612e609'),
           ('753974457', 'bb857f1acc624a799d8999b6b77b3d53'), ('753974461', 'fda62703d2bd4177bae910df305c56d3'),
           ('753974464', '8b37f8661e814a6aa31efeab985686cc'), ('753974467', '13481f3cb8af486fb8ccc8165fda27ce'),
           ('753974470', 'b27335b29989419f8c13d60894506964'), ('753974476', 'b8e98c9e789f4b44ba0efd8a02bffc37'),
           ('753974482', '235a259e75bd4aeea3da34a549357535'), ('753974489', 'aeeb5b1a269948f8a05d0f4a67d9c39d'),
           ('753974492', 'bbc480aa715848179bc7c89c9337faec'), ('753978460', '97a5ea3936ba495097d67c338fb809ac'),
           ('753974512', '80b2203f052e49519d4dfbec3f4d9838'), ('753974514', 'c8ff6bf4362a40729ca0d0eb0541fcba'),
           ('753974517', '022c5f25d30e47548ec0e410f28facf1'), ('753974543', 'a277745556f74045b05083b903d1bf08'),
           ('753978480', 'a937b2e88c834bea9dc440feaaf1cd16'), ('753974567', 'f5714f1608f543b8878a407077e2b1a9'),
           ('753974569', '7324ebc0764143368c23a08053290aa1'), ('753974572', '0a172673a32d4e6cb059d2022312826e'),
           ('753974582', '5a48f35368cb464e8b5b5e2c3bc2b7e9'), ('753974587', '13b1feaef06f4631925f3d4c28c92425'),
           ('753974588', 'b01d5da3eade41b9a266ed305dbfcbb5'), ('753974591', '8dffac893f9d428fa4997b5f3ad1c102'),
           ('753974593', '69657a722ff44691a1a79914d33cfc34'), ('753974602', '10079ff186dd4f0885200e9e549e260d'),
           ('753974614', 'b10a8eafe1764e449286cfae5141fe96'), ('753978576', 'af894f877fe34bfab4bf08fce7714207'),
           ('753974642', '8cb65078a3be4313a50aa927cba518e5'), ('753974650', '5782a16ff75d493599951a8a26aeeded'),
           ('753974652', 'f56e4d5a2dea41b49beb2f26011daefb'), ('753974655', '3950eda69da34ca9993f0b048fc08faa'),
           ('753974658', '95314b4f94224f2f870eae215748152e'), ('753974670', '2c96edabc8d946de84f3462224caa772'),
           ('753974671', '3110a5189e1840238bc7eca6cde58f2d'), ('753974675', '3c583b0e8f274538b0252afb57ae7a31'),
           ('753974679', '46ba3581e40446f78f39201759049691'), ('753974682', 'c139b79a2b05496c86dab26b9f5a93d4'),
           ('753974685', 'e348ad7e27254123ad994c7d1e035819'), ('753974690', '41bebbb3abac4532a2b3cc531e4f7226'),
           ('753978650', '36474783db904768b6aad21328ba4b4f'), ('753974705', '1a0ebe76c6244a75b893872989caf0c8'),
           ('753978667', '6652af69c495470dabca2dbadac30a9c'), ('753974724', 'b9e97b4ea4c44b01a96fef905727876e'),
           ('753974741', 'd405b21706d94584960586d36118239c'), ('753974745', '7f8528fea7cc4cca9a62e6c637221bb3'),
           ('753974750', '4949648c726c411a88f372efde783a52'), ('753974768', 'ed94b0a050d0440b820f16b42e2ee6cb'),
           ('753974794', '4ed0ceca427a4881ac75d55fa71d2cdb'), ('753974803', '8e0a1d6221a14908a282b1b4e233518f'),
           ('753974808', '2fc69f60eea240e799104ab1008317f9'), ('753974813', '86e2d790c6274e85974f82b562b4d21c'),
           ('753974817', 'c37a558dcf044b23a9c8c84f9b2698b4'), ('753974819', 'ae4ae2b33a3149caa6610e8436c2ba61'),
           ('753974821', '1d664247eb8e4da8ac5af4289433199c'), ('753974825', '8306ac2fa75e48a8a1d411ebbb21d34c'),
           ('753974831', 'f4a2ed52951343fca4b33248b830a03c'), ('753974833', '72954d74f0e547888c180c8ec8cbcb75'),
           ('753974837', '36534e82572e4364bdbc4a0922a75883'), ('753974839', 'fe47e9d491fb4194b57b0f81b50078bf'),
           ('753974842', '2d8e994d3a6043209e5e31970e4fd137'), ('753974847', '61dc1a3b21db45c7988c5bb40356cb44'),
           ('753974850', '625f6e7353c84030a941ec08738fbda2'), ('753974854', 'f582d12316934e9885a157743839173b'),
           ('753974855', '52f7a32026004a069b2dc89b225480e3'), ('753974858', '13bdf91cffbe414d97b4d3feac19e468'),
           ('753974860', 'a527a0f45ed8423e90e15fccef3a58c3'), ('753974862', 'eb088af55ded4f0aabdbd232c1ddc4f3'),
           ('753974867', 'be4e0c38205b416dbe3393229fa60f1f'), ('753974871', 'ba6e868f476b4ce89c24f3cba7082ebe'),
           ('753974878', 'cd2f8fb9bace439cb0785b9ea9d9f885'), ('753974881', 'cec6b680e9144562b1a47f517912760a'),
           ('753974892', 'b80cc6122c254e73af52be801b298ccc'), ('753974910', '13363bee2ef942abb706c7eeb4b0f7c5'),
           ('753974912', '7a7e8ae4bca54ae1bdd1c68419d2eeae'), ('753974913', '45ebc790bb924087bbe630928c61ed76'),
           ('753974932', '1a4df5d99b9e4b99b15f610d5904281d'), ('753978915', 'ff6717dd7cbd4e448af7a6941691b34e'),
           ('753978918', '94c58e5325ba44d59ad340517967165a'), ('753978920', '23e667d284664c908a236092126e5aa9'),
           ('756774996', '6e6fb190d9ca4185844486df81bdb98e'), ('756774997', 'e46156a10b02432687ef5449cc1054f1'),
           ('756774999', '647dcd2db27a498d967e7ace0c0ef34f'), ('756775001', '78a4117d97424b95a77e29ee69e99c11'),
           ('756775003', 'fec8c55a76d24bf69b9521ee882ccb3f'), ('756775007', 'd04223f8dddd497b83c07166a376d0f1'),
           ('756775008', '2d59612ed48d4af2a8c7fbce73a7f6b2'), ('756775009', 'df3efbe5d233486f8183d16033711da9'),
           ('756775010', '1f050ac62df043e88e6ac920780c7bee'), ('756775011', 'eaabb266f46a4a2092044fa3c03a4bb3'),
           ('756775012', '75a00f464b3b4d188b87a955cde8cfef'), ('756775015', '351a512871df4bf8939005f96cac2bc5'),
           ('756775018', '3c2708f286ec4a169b12c00bcdba92d4'), ('756775019', '97ddfb5bf4dc4214a81ff0b9d10c1db1'),
           ('756775020', '668e73c0651043b1ab550717d07e3d27'), ('756775022', '1ac360fe96ee4388970f2143cd460bd1'),
           ('756775023', 'dd0356e9ba4e451090c306b7fa82086f'), ('756775024', '1966f1ff46174827b6e377616a52a717'),
           ('756775025', 'f500ae78a1494d7f82159239037413d9'), ('756775026', 'e9c3ad2ae8b7450798e326bc941791da'),
           ('756775028', 'f6953f9b05d04d51b265c1c16b03f123'), ('756775029', '714da992bb6d4d6ba4bb1e872040134a'),
           ('756775033', 'c14244f500a946fe9ccb25a28e58cf7a'), ('756775035', 'b0384cfb86754d9e8c9c7e4e1b75993d'),
           ('756775038', '0e348c3679fc41e981253c65618bfdb7'), ('756775039', '71ad19eaab8a498ea5af0ccbad8315b0'),
           ('756775041', 'e0266b4af85b4bfda5eda7d201ffeefe'), ('756775042', 'c9313105a8114f83a0120c79a4cff906'),
           ('756775045', '02abe358adda404098de5b47d23dad41'),
           ('792778058', '9b3087bd298e47e880c342155a26332d'),
           ('756775046', '00642c81cd994a25a8008c379267c626'),
           ('792778119', '0a902f37e99e4688b44aaefc80bca367'),
           ('792778121', '5fcde5d3c3f542028ecf4cbb4faae6b3'),
           ('792778125', '294e7a70b3bb4e99a95a94e7f62e09ce'),
           ('792778126', '2d649db63bee4477bcec838735f2bab3'),
           ('792778129', 'c5793367e91b41d9bf03b51dc5229114'),
           ('792778131', '02930f38266e41b6af876d5ffac493e4'),
           ('792778133', '8102874fdb904c01b7dbfa7a27cbb2c8'),
           ('792778135', 'fed93f6f771c49eead303cd1cfe5ba7c'),
           ('792778137', '011e8f21f5484e8789e7398dc483f726'),
           ('792778139', 'cfbf78539b4e4461bff225b06110650d'),
           ('792778142', '30a2c979a1cd4a02b91d8830442f5a36'),
           ('792778145', 'ce785fb5f8d742608c8f4d1cbba97ad8'),
           ('792778148', '5ee14308b59745538ff07da74a43db17'),
           ('792778150', '8bb6a10f9fe846b0af15fd6c2cac4fbf'),
           ('792778153', 'abec0efed05c46d09fe80aea32bd01e1'),
           ('792778154', 'a41d4786261a4794b891dc7403ef241f'),
           ('792778157', '95ec75f9207445ecabdb65db63c63906'),
           ('792778159', '9240e11f63ed4913904488d992333de3'),
           ('792778162', '3150384edbf74117afcfccac9e6e5d00'),
('792778163', 'ae14283a5f6746d0825de983c9eae72e'),
('792778165', 'e0ca9f4565bf48648601f66006fdafb0'),
('792778167', '854c02674d564e57a8a945e7b0352850'),
('792778169', 'd0d338edf301471dbf23fbf8f5b64c99'),
('792778170', '2b04ad58842b423a9a4f37d88eaed093'),
('792778171', '879c18419ae14f4081eedad7c63fce37'),
('792778173', 'b55e8f5b6a554715bc878e83c399a933'),
('792778174', 'b9c7bd878d0a462e8b5325d419afcd3e'),
('792778177', 'ffcee06c2cf849caad192a6083aacc66'),
('792778180', '24a3f4c5c2224f7ea2bcc815ddda7709'),
('792778182', '565d9dbb48974dc791a7b0ac7c9cdba7'),
('792778184', '57c83add99514bfdae8a52f64f052f1c'),
('792778185', '6a13b357184542c1b567925579ba2c84'),
('792778188', '1671ad1592414cc989d225313058d233'),
('792778190', '012b6ba1a9a641d0b4442feed494de3a'),
('792778191', '4cf1853d813046a3b35548ca2f34b1c9'),
('792778192', 'fba5b7082077477a8eda203fffc1c5b1'),
('792778194', '857f0431f5e04a52be7008b4a104628b'),
('792778196', '9de7b0df33fb40dca4f776111e227dad'),
('792778198', '2d8300b2d962440596f57374e36f1993'),
('792778200', 'd2780506793842ed982fa8649752d7ea'),
('792778201', 'dd0a3d909a7247cab14ea80b4151bb50'),
('792778203', '79655b7054f7465d9d4e94fb3301b873'),
('792778204', 'a0aef337e1554fd496d214124d5ab744'),
('792778206', 'f534485476674301ae38794d975073d3'),
('792778207', '7051a706750047eb9cb8914bcaf7c1d9'),
('792778209', 'b56020a6383b4218aaf9f57e1623cfac'),
('792778211', '71ddb60ce4754387ad6a63851d87779f'),
('792778212', '1bbcfc25c2e64219bdd5011dbb506fe8'),
('792778214', '0feca5db1ce54f12a3c33013c4d7be2c'),
('792778215', '6f64a9de986148c0babf82427ed12226'),
('792778217', 'b65fd304fce5434ab7d217c95e4bf96d'),
('792778221', 'b10c1e72d9ed49f485666a0a7d73b788'),
('792778223', 'd211169f48df4b3295ca838825187eb4'),
('792778225', 'd2241292907c4cda985b1d5ac210913b'),
('792778229', 'df6966a657744bc58f63835bdbfbb47e'),
('792778231', 'd30cd483580e4f7d9d1d8f1b604ea9e7'),
('792778233', 'f2fc0383660e454caa76ebc610bd8f6e'),
('792778235', '4ff28a478a3c4c889f3b4997e5a0a92a'),
('792778237', 'def88a863532409b860f626260de2d7c'),
('792778239', 'a44d6b0439a94068863cee58231db283'),
('792778241', 'e1be77e5a436488db2c111ce566c6bea'),
('792778243', 'b13b3035afee4622811ce948fd218fd9'),
('792778244', 'ec1847e392c146b8963494da43189085'),
('792778246', 'e9cdaa4e7fc248c8af0e06242f70968f'),
('792778247', '44b68b9be134468188dcbb1641f888b0'),
('792778249', '0fe159976b174866be1ad044f1627461'),
('792778252', '00f683c4c9ef4a1596929cebdbb3e64f'),
('792778254', '5c2c3e48040641249a5ea1dc4d22db0d'),
('792778256', '0fb2e7e5d76f46b08f11d08d718f9811'),
('792778258', 'd3b61320cc6d4c0fb45847b9496dfe62'),
('792778260', '612fd1728b4e4261b14575356438f8ce'),
('792778262', 'd82950b89e6149e4b951f3b66d6cf278'),
('792778264', '3c4d2af1938c4bed906a19e9ada4074e'),
('792778266', 'ca02e1f31ab2450b8aa0eb1256c22b85'),
('792778268', 'bfc6b167985f48ea8a66e1e2d4748ecf'),
('792778270', '26a945b00b914a67b2762c62b3b0a7e9'),
('792778272', '947553aa379b4b95870fc2d0e03af48a'),
('792778273', '3f947f62107c4b15abca0502db10e577'),
('792778275', '09b9813498d347f3931423ee3d3a4c15'),
('792778280', 'fdd0808979ed4a1b963f43c1635e47cb'),
('792778283', 'e80defab32b2477199ea18ae689f98bb'),
('792778286', 'cc8bec6645e7412ca795039f20e9c254'),
('792778288', '466034c8857d419ab2954de46d92371c'),
('792778290', 'ea97bc5e2a46429bb2da9eb5815c487f'),
('792778310', 'c006d7d1b6ad4a03b30c8473b6784b12'),
('792778312', 'c4edebc75cf8400a971dd0b95cfafafe'),
('792778313', '9f8a70abd6024ee490b04657edf8cb5e'),
('792778449', '5a1e7b9327ad48158009492525d3bac3'),
('792778451', 'e284f983178b4648adf4732ff7164f84'),
('792778454', '7d39a8ec54e4446ba04f970618a60137'),
('792778455', 'c69951d6bf494168906de4cb0d188646'),
('792778459', '921a3dbe190f471cb2820e4b05031f62'),
('792778461', '2683e2e330764d0490f49c14cb2dc5c2'),
('792778463', 'b1edff17d2584c1290f2c5c4b3c9e184'),
('792778465', '32d7f507899f4e549e819e176c9304bd'),
('792778467', '538ce3a34702431bb2b6683d590bf30f'),
('792778469', 'fceab36654a745d7871943fe1b189e37'),
('792778471', 'a1fdcf62eaea4ef29f9ea2948a9a74bb'),
('792778473', 'df097ae76f33418697ff2e13f8d9a116'),
('792778476', 'd72951132ea94510a402db9388a8dea1'),
('792778478', '031a5718ea594c0ba98a63b3c2840970'),
('792778481', 'a5a1569160e8482691258d246891a634'),
('792778482', '7f5da3afb51c42469c1b8ae55d787e4d'),
('792778483', 'e9d714d19b394d84aef8d8eaddd61913'),
('792778487', '5507524fed244cbc8d9b94b90f5be6fb'),
('792778489', '8801c8af71634965b04b5f28722e04d0'),
('792778491', '0428c804f83c429b858c67c09f884081'),
('792778492', 'e19d281b4bab4763a33bb4e10c4ceffa'),
('792778497', '552fe0a2ae824f75a447b0c8627bce1e'),
('792778499', '5210b93e078c46a3bb6e36be48257b43'),
('792778502', 'd983efadf2c1492da4c9132be0d926c4'),
('792778503', '131d9400d9f440bfb1c8734fc3b722f3'),
('792778506', '0e364bfed02b45f2bd9dd22b5c7c87f3'),
('792778507', 'c7dbef51ff2d42d780ebed6432ba4006'),
('792778509', 'e102ba250cea427a8fd0cff8c2387a95'),
('792778512', '83facd1a660046dba9b07b0c42345c4f'),
('792778515', '05f710d24af74cb7be7839b8d5375407'),
('792778517', '5ce49fba08574625851609e37affda9f'),
('792778519', '5acab072c32843af9b48b03a6ee8415f'),
('792778520', '995663734325486aa02cf2d761282d7b'),
('792778521', '9d6b7e905721419f9e7ab9b349db57b9'),
('792778523', '6dfaa8026efe48679e5542cdfeade05a'),
('792778525', '4f4e39da804f4c1ea8b1fd729892ae77'),
('792778527', 'a4395bb3d5994abea2513e0a749586eb'),
('792778529', '19186d17e5a24a54bb620b538a6d7b8a'),
('792778530', '15f286b104a742ebac8f71864be37bb8'),
('792778532', 'e737ecc19b7141868428188ffb9e3c3d'),
('792778533', '673388e6302a41a29a712037cf4f8ce4'),
('792778535', 'd5b6a565c1b5403bbbbcf78e41625e23'),
('792778537', '25ac79add0c248099521b7f5a92edd03'),
('792778540', '89304bfef9b346d3bb8ba374b1706721'),
('792778542', '92d45d8c9eb849c594d2201a493cc3f4'),
('792778545', '7f58d137273c4949beb6968a70ec5711'),
('792778547', 'd08a8a5a8c3f4e4eb5b6ee59a08f4a9a'),
('792778549', '29af261046d642afa291b307202cc4f8'),
('792778552', '52d42f1cc128482f897a1602e99b43ab'),
('792778554', '32366aeb2dae4e67ad3dddc8c272a642'),
('792778555', '908d7c31324b48f38e4c93a2c1b4f081'),
('792778558', '22a3455e70f04b3c9159222f34dcaa7f'),
('792778560', '491226080fb34bf3ad7f18d1c4c55ee0'),
('792778563', '7a27a5038a624607950e9a0be8184cb1'),
('792778565', '68cafcb2cd9843da833242f2244a6cea'),
('792778567', '9391a9befea64c6f9fa50d33bbe0a527'),
('792778570', '65376ccb1a3a4edb8a43d57daf18c4f6'),
('792778572', '3ebe5793954d4d4b9e0e357500d5b136'),
('792778573', 'd8e0e8286f0e481a9163f3a395aec003'),
('792778575', '0ef562efb0e64c05aefb2c5068009c28'),
('792778578', '5efe11983db1421bb7df6d36be8367dc'),
('792778580', '9b38ab3817374baa879bb25d0f06bcb4'),
('792778581', 'a4e283a2f0f2456db2a59f8a6ff72f5e'),
('792778583', '34967a816d6e44b7bf8432360a5622d7'),
('792778587', 'b2ebb7a1884b4eff8ea73b8a68c48c20'),
('792778589', '3ec4be4373284aa490c9ffef4d21ab2b'),
('792778592', '8ad5bf6e77c64a4883c9e34b4e8bcf32'),
('792778593', '46abfe06c0bb4d94bfadbecdfd88319a'),
('792778595', '14e5db7bd87e456eb0053893907a4a6b'),
('792778597', '70e3404c06ee4f72aaf80be1be20d92a'),
('792778599', '650342e114d44914a19bbef17ace4f1a'),
('792778601', '1d6d9a1d42df491d924e060f714f8c8a'),
('792778603', '867d4c76d6cb487ba2d8e4b3a43e470d'),
('792778604', 'adaea21bf6e34e0db44d2838e3bdb393'),
('792778606', 'c081008ad27544e592f41de918b305ad'),
('792778608', 'd14349fb00e7429085be8c6b3cc49ead'),
('792778610', 'a46f58cb9cd64e5ba21d14d6e7fe127d'),
('792778612', '0da36bd7cc474561aecfe4baecf574e2'),
('792778613', 'c4fce5931bae4c33b3a5e480472a30be'),
('792778616', 'a90e29c107e84b9baec6f1762eaa5408'),
('792778617', '902f5486e46e48aaa7820052fad2bb9b'),
('792778620', '3f63041c58774e6da77b2dd562c9a687'),
('792778622', 'c3d0c5f710c64eb5b4d5271a48b8303d'),
('792778623', '8294db73fdc14dc1b013018eae924458'),
('792778625', '27b1eed8f1e84515a3b092cf95539c99'),
('792778626', '15a40c9b187d468f99d54de8ee1c08fd'),
('792778629', '7df267c724a447bab74a3cd29519b4fa'),
('792778631', '44899dd3010e4eafa02b17b78b0567f4'),
('792778632', 'd92068a310f443d4a3c7604414f7c93c'),
('792778634', 'ee52597bfce546429be8cc7e3f87dafc'),
('792778636', 'e38dd40f9c77434fb91e1fdc3b1337ab'),
('792778637', '9a4d740d5bd94c2da11084d0acebb8f3'),
('792778639', 'b919926344b54d409469c4edadf336bb'),
('792778641', 'fd7f16ae55f84c93a3f0c5d9fcfffece'),
('792778643', 'b63e6de3111c42cb97610218bd29a7e5'),
('792778645', 'ae559c2f295f45a4b280a29c4e76a545'),
('792778649', '217e3b52976e47bf932bcf2b004db08e'),
('792778651', '337a8ee80c2f4774a81c9bea7b666e9b'),
('792778653', '6e7f808f238d4514a89cc82e19397f18'),
('792778655', '22b2009af13b490f8ae67178e22a935f'),
('792778656', '3fc3674313704d42a6770d61dfc3d9be'),
('792778661', '51a154b6db0943989a9d94cc850d5143'),
('792778663', '91f5f9311f11414da98a3f8cffa233e7'),
('792778683', 'a16b12ba72d8497489c47d8a7e674569'),
('792778823', '80b66644d41f4ced9f78cddc8b4a1a72'),
('792778825', '7cbe5a5d891544699ad53874e4134302'),
('792778827', 'd7fb65bf402946dd999598cce749c5e7'),
('792778829', '69d8f7f8850e4fb894c305043e0a65dd'),
('792778832', '68b4f4521c514e0c812368cd763d45fe'),
('792778833', 'b85de76961ff4bc9bb68f453de30b2ef'),
('792778835', 'c517e36218cb4f34be798fc6071b3eab'),
('792778837', 'a3101f4db36b40c5ae9012dc2faeac7b')]

def make_庭院点赞(id_0, skip_line=False, skip_游玩=False, callback=None):
    level_id = id_0 if skip_line else input("请输入关卡id:")
    r1 = None

    游玩线程 = []
    点赞线程 = []
    start_time = time.time() 

    for i in range(len(packets)):
        def make_庭院游玩线程():
            nonlocal r1
            j = packets[i] 
            data = {
                "req": "V733", 
                "e": {
                    "id": str(level_id), 
                    "pi": j[0], 
                    "sk": j[1], 
                    "ui": j[0]
                }, 
                "ev": 1
            }
            suc, r1 = send_加密发送_拼接提示(data, "游玩关卡{}第{}/400次".format(level_id, i + 1))

        def make_庭院点赞线程(): 
            nonlocal r1
            j = packets[i]
            data = {
                "req": "V722", 
                "e": {
                    "id": str(level_id), 
                    "pi": j[0], 
                    "sk": j[1], 
                    "ui": j[0], 
                    "t": "1"
                }, 
                "ev": 1
            }
            suc, r1 = send_加密发送_拼接提示(data, "第{}/400次点赞, {}/{}次循环".format(i + 1, count_庭院, i_0))
            if callback:
                callback(i)

        if not skip_游玩:
            if r1 == "ip被锁":
                print("ip被锁, 请等待5分钟") 
                time.sleep(301)
                r1 = None
            t = threading.Thread(target=make_庭院游玩线程)
            游玩线程.append(t)
            t.start()
            time.sleep(send_多线程延迟)

        if r1 == "ip被锁":
            print("ip被锁, 请等待5分钟")
            time.sleep(301) 
            r1 = None
        t = threading.Thread(target=make_庭院点赞线程)
        点赞线程.append(t)
        t.start()
        time.sleep(send_多线程延迟)

    for t in 游玩线程:
        t.join()
    for t in 点赞线程:
        t.join()

    end_time = time.time()
    # 本轮耗时
    round_time = end_time - start_time
    print("\n本轮耗时: {:.2f}秒".format(round_time))
    return round_time


def make_自动庭院():
    data_创建关卡 = {
        "req": "V723",
        "e": {"c": "100", "f": "0", "k": "0", "pi": pi, "pk": "0,1,2,3,4,5,6,7", "s": "0", "sk": sk,
              "t": "2", "ui": ui, "w": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19"},
        "ev": 1
    }
    data_发布关卡 = {
        "req": "V720",
        "e": {"checksum": "17fa41ddfa6df19ef32144dacbccc1ce9818993ceea836111e5a28cc5ad4f3c2",
              "ci": "5fee890da2865d97789b57999318e8e8", "dl": "1", "id": "0",
              "lvd": "H4sIAAAAAAAAA-1dW5OquBb-Q_Mg2O4pHrctIFSL1QgJ5M2Q3gck2NbgBfz1sxLAS19q10zNqbPn9HqwhJCVfFlJ1rcs4-dL65feZve7VwU1e_S-vbR-wse-vva2LM9M8iPd-jKle5kVXu2VjRQVqVfxc7EsPINVRC5n5Ym5drucpQablePg_J9JuonHy6icLM72A4tyuXy82sau06bUOOt-ZbgTbiO9zWvhFacidMk5Hfu7bB7uuPmg-iieHv0FS5jk9sTg1Fc4vi0eT0U8DvNsC_UqEQkKdTfeSZUT0zFZHObCtYvltoZ601yYkxk3G4dXgHvzvfZkcEoTcXg2rbprZygXOWCMMpccmCsPzJge13QyWtHJJqvInsE1YD0BpiQFTNC25JXG8MxNeRDzxW07aowcfOrA9UE44SRz4_757ghj2bEE6sv975d70tfpxr3mplGsKXnmrrNhxD-K1vv2FNkXXwKW5seqQXu0R_v_lT0Zwb1TQrwYral1SGmj6h-Ey47c7ONKScwudqiYF-QQMyLhWi1f6ZirYhPEtsk1PpXBkc_JnstglCb-EHMGPDqueCoef_ryBdSPX5Kpiq2nHysVL6c75pI2rpwdL_5SvxAPZckSqD-GOPY4xN-uPVpZ-7SSMqqcPYPxQN8W2DwDj4xSeupiMIxVuE6t4q2gxqFvt6_TrPg46-Pi9AgxPefOdR4U9hBiMTd8o8dtQ0w-xpU1hnb2C3hOXLlnMcRfwCMqp9btb6YKxyqlsoT6W8U7Yl72nCCA2_JC0OAPDjaAy-CKA4pRo_vb-sdsHCZg1_GjFBDjQ-33JBkpnHlWOZv1nIxgXeRrxT_Q7jC-UNsBNlW39OsU-lm5Vs2u872Eet06seU5nPs5M4VUvPsUOdYPsEPeQHu0_z-2R95A3kDeQHu0R3vkDeQN5A20R3u0R95A3kDe-HX2Ddqj_Ve2R95A3kDeQHu0R3vkDeQN5A20R3u0R95A3kDe-HX2Ddqj_Ve2R95A3kDeQHu0R3vkDeQN5A20R3u0R95A3vjX8IYh9JyZRDLbh_Wyt9MkzDWWvr3IlWc1F9TQeFqWBFLYzS4bwzhkXajf0X_6ksrmho_UvG-ZfKFWe2l3rOatyfk21OvoOr-e-l27XFPxOqyFyFXr-9T7T-2nKWCcjMhcnlg8yTm97KmEUbldz4f1dtlH2lfgm84nev7JMqXGRROAmGTHzHxYk50WQO-vpzli_RyroWLBnLtWAXvtHsujP1vDvuRK58CM9Rr-RHvBhvW1ySp5Eq403_R90wa5WadNDnsI4pxz6DUl1DXEAa2noMfBKuvYrXlbaTHomKP3KsSZIW5FFPaN0lMAbPraFu2adnuRnr_X4KfT0-z-PVk1_KPyp9lUPDn1B-Xw7ozqv9NeFw8U9tBgsZG_VJ0fYe8qvYiKj3WOp_dzmLAdt8NcDHXeaVfoGKh9E6p9CL5LTb1HDzrmduvGgVc78EAC7Q4x-Nrfz_a_oeY-5mMhszKUDPLTfo6es4qcWRL2sekvxZOWUbJYJ8FowPVWg0Pfv8153-XAavyBvI3vw_j0uh84BvbRUK78kpqk4xHYKzdcOXBg4W31nv2c0z_IAe5zA8SFuP5hXMS46ydrO979sv5AXF8WV5Lc9TNoJn1ZfyCur4pLffZrMD9CXIgL8yPEhbgwP0JciAvzI8SFuDA_QlyIC_MjxIW4MD9CXIjrJ_lR9_28f0zp7fmdQH3nXrM4V2ex5GfnE654veG_HK7nG-7_2wF5B3F9cVz6nJGXJsH9-ceK5XweSOQkxIW4FCepM6F5nr05A8cqp85Mgp_nERfiUp_noXzlOuf-zGPFTUudxa5S2pwZftZHXIgLcy7Ehbgw50JciAtzLpxDxIU51y_mK8T1ZXFhzoW4EBfmXIgLcf23cy5idJojnZ7GAbjm5rt-lgPfPGYVydcmaTttAmPHB62TEuq75AH6eYA2gjTJB10UX50NeAHOWj6eClI5Z6UxMrQNfrroqwxaKxcth21g8IrV-vf16uwA9CW0_sur0fnrVgvqvX7ERY9EaZiArwbfKQ2AD7Qfrroscz1_n-O6x3L6N2NJEsPSmgq0kZxCn71GRB9HYe7YUecVSh-l1JoRvnDJ_laT4Wat3deXStOl0WXdWQ99v1H6FJd1vL2WJSaMw_SPLytvsJ2p8jd9KS2a-q0mROxaY5b4MdjId3oRdLIBf7YpFbJbt_L8pqzjCaj7vCUTpZvBqXVgidK5CVtBY6U_Y7yQ-xxMzH1jsImo6t_r6xPt06giI2Fa7XrU6Yis4kFXZCLFXByzat_piNjD3PuZiL6fWBTq97Ry9PsyGspJdz_Lu-cb8ZP6Q73eDvoA_y1ZEo752P-DADbuhsPaapYfYIZxlWqegvb2GTmk1K9ZHMJ8TWpuOoprR9mWyNv2nxMyWrtWe79WL2OfiiR8hXoeo06ZmfkRYo7dr_ErxmSq22c0hLm9ruELFoOcmOuM3j3Xmi_NJfaofabyg7CSh3USvEL9i4bLMI_q-bW_a1xU2jPcDHLuvOurCc62GWwWxmJjm33snGgdpZWKdw_n5cybLCKpNOx--xMJYu-tIIgAAA,,"
                     , "n": "互刷互赞", "pi": pi, "pk": "7", "s": "9", "sk": sk, "ui": ui, "w": "19"},
                     "ev": 1
    }
    
    suc, r = send_加密发送_拼接提示(data_创建关卡, "创建关卡")
    if suc:
        suc1, json_object = send_加密发送_解密响应(data_发布关卡)
        if suc1:
            print("发布关卡 成功")
            round_time = make_庭院点赞(json_object["i"], True, True)
            data_删除关卡 = {"req": "V727", "e": {"id": json_object["i"], "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
            send_加密发送_拼接提示(data_删除关卡, "删除关卡")
            return round_time
        else:
            print("创建关卡失败")
    else:
        print("创建关卡失败")
    return 0.0


def make_自动庭院主程序():
    global i_0, count_庭院
    print("请输入执行次数")
    i_0 = input("请输入次数:")
    print("输入完毕, 大约需要{}分钟完成".format(int(i_0)))
    round_times = []
    for i in range(1, int(i_0) + 1):
        global count_庭院
        count_庭院 += 1
        rt = make_自动庭院()
        round_times.append(rt)
        print("第{}轮耗时: {:.2f}秒".format(i, rt))
    
    total_time = sum(round_times)
    avg_time = total_time / len(round_times) if round_times else 0
    print("\n总耗时: {:.2f}秒, 平均每轮耗时: {:.2f}秒".format(total_time, avg_time))
    input("自动庭院已完成, 请按回车继续")

def make_点击庭院():
    data = {"req": "V303",
            "e": {"al": [{"id": 10840, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0", "pack": "",
                  "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    send_加密发送_拼接提示(data, "进入创意庭院, 获得紫币（如果有的话）")

def make_踏春之旅任务():
    d = {"req": "V303","e": {"al": [{"id": 10851, "abi": 0, "type": 1, "config_version": 1}],"ci": "93","cs": "0","pack": "com.popcap.pvz2cthdbk","pi": pi,"sk": sk,"ui": ui,"v": newest_version},"ev": 1}
    suc, r = send_加密发送_解密响应(d)
    if not suc:
        print("获取任务信息失败")
        return
    if isinstance(r, list):
        r = r[0] 
    try:
        data_str = r.get("data", "{}")
        data = json.loads(data_str)
        task_list = data.get("task_list", [])
    except Exception as e:
        print("解析任务数据失败:", e)
        return

    incomplete_tasks = []
    for task_dict in task_list:
        if isinstance(task_dict, dict):
            for tid, status in task_dict.items():
                if status == 0:
                    incomplete_tasks.append(tid)
        else:
            print("task_list 内非字典类型:", task_dict)

    if not incomplete_tasks:
        print("踏春之旅限定所有任务全部完成")
        return
    for tid in incomplete_tasks:
        if tid.startswith("1"):
            type_val = "0"  # 每日任务
        elif tid.startswith("2"):
            type_val = "1"  # 每周任务
        elif tid.startswith("3"):
            type_val = "2"  # 限定任务
        else:
            print("未知任务id:", tid)
            continue
        req_data = {"req": "V432","e": {"pi": pi,"sk": sk,"ti": int(tid),"type": type_val,"ui": ui},"ev": 1}
        suc2, r2 = send_加密发送_解密响应(req_data)
        if suc2:
            print(f"任务 {tid} 完成")
        else:
            print(f"任务 {tid} 完成失败")
    make_令营领取()

def make_查询庭院():
    data_创建关卡 = {"req": "V723",
                     "e": {"c": "100", "f": "0", "k": "0", "pi": pi, "pk": "0,1,2,3,4,5,6,7", "s": "0", "sk": sk,
                           "t": "2", "ui": ui, "w": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19"}, "ev": 1}
    data_发布关卡 = {"req": "V720",
                     "e": {"checksum": "17fa41ddfa6df19ef32144dacbccc1ce9818993ceea836111e5a28cc5ad4f3c2",
                           "ci": "5fee890da2865d97789b57999318e8e8", "dl": "1", "id": "0",
                           "lvd": "H4sIAAAAAAAAA-1dW5OquBb-Q_Mg2O4pHrctIFSL1QgJ5M2Q3gck2NbgBfz1sxLAS19q10zNqbPn9HqwhJCVfFlJ1rcs4-dL65feZve7VwU1e_S-vbR-wse-vva2LM9M8iPd-jKle5kVXu2VjRQVqVfxc7EsPINVRC5n5Ym5drucpQablePg_J9JuonHy6icLM72A4tyuXy82sau06bUOOt-ZbgTbiO9zWvhFacidMk5Hfu7bB7uuPmg-iieHv0FS5jk9sTg1Fc4vi0eT0U8DvNsC_UqEQkKdTfeSZUT0zFZHObCtYvltoZ601yYkxk3G4dXgHvzvfZkcEoTcXg2rbprZygXOWCMMpccmCsPzJge13QyWtHJJqvInsE1YD0BpiQFTNC25JXG8MxNeRDzxW07aowcfOrA9UE44SRz4_757ghj2bEE6sv975d70tfpxr3mplGsKXnmrrNhxD-K1vv2FNkXXwKW5seqQXu0R_v_lT0Zwb1TQrwYral1SGmj6h-Ey47c7ONKScwudqiYF-QQMyLhWi1f6ZirYhPEtsk1PpXBkc_JnstglCb-EHMGPDqueCoef_ryBdSPX5Kpiq2nHysVL6c75pI2rpwdL_5SvxAPZckSqD-GOPY4xN-uPVpZ-7SSMqqcPYPxQN8W2DwDj4xSeupiMIxVuE6t4q2gxqFvt6_TrPg46-Pi9AgxPefOdR4U9hBiMTd8o8dtQ0w-xpU1hnb2C3hOXLlnMcRfwCMqp9btb6YKxyqlsoT6W8U7Yl72nCCA2_JC0OAPDjaAy-CKA4pRo_vb-sdsHCZg1_GjFBDjQ-33JBkpnHlWOZv1nIxgXeRrxT_Q7jC-UNsBNlW39OsU-lm5Vs2u872Eet06seU5nPs5M4VUvPsUOdYPsEPeQHu0_z-2R95A3kDeQHu0R3vkDeQN5A20R3u0R95A3kDe-HX2Ddqj_Ve2R95A3kDeQHu0R3vkDeQN5A20R3u0R95A3kDe-HX2Ddqj_Ve2R95A3kDeQHu0R3vkDeQN5A20R3u0R95A3vjX8IYh9JyZRDLbh_Wyt9MkzDWWvr3IlWc1F9TQeFqWBFLYzS4bwzhkXajf0X_6ksrmho_UvG-ZfKFWe2l3rOatyfk21OvoOr-e-l27XFPxOqyFyFXr-9T7T-2nKWCcjMhcnlg8yTm97KmEUbldz4f1dtlH2lfgm84nev7JMqXGRROAmGTHzHxYk50WQO-vpzli_RyroWLBnLtWAXvtHsujP1vDvuRK58CM9Rr-RHvBhvW1ySp5Eq403_R90wa5WadNDnsI4pxz6DUl1DXEAa2noMfBKuvYrXlbaTHomKP3KsSZIW5FFPaN0lMAbPraFu2adnuRnr_X4KfT0-z-PVk1_KPyp9lUPDn1B-Xw7ozqv9NeFw8U9tBgsZG_VJ0fYe8qvYiKj3WOp_dzmLAdt8NcDHXeaVfoGKh9E6p9CL5LTb1HDzrmduvGgVc78EAC7Q4x-Nrfz_a_oeY-5mMhszKUDPLTfo6es4qcWRL2sekvxZOWUbJYJ8FowPVWg0Pfv8153-XAavyBvI3vw_j0uh84BvbRUK78kpqk4xHYKzdcOXBg4W31nv2c0z_IAe5zA8SFuP5hXMS46ydrO979sv5AXF8WV5Lc9TNoJn1ZfyCur4pLffZrMD9CXIgL8yPEhbgwP0JciAvzI8SFuDA_QlyIC_MjxIW4MD9CXIjrJ_lR9_28f0zp7fmdQH3nXrM4V2ex5GfnE654veG_HK7nG-7_2wF5B3F9cVz6nJGXJsH9-ceK5XweSOQkxIW4FCepM6F5nr05A8cqp85Mgp_nERfiUp_noXzlOuf-zGPFTUudxa5S2pwZftZHXIgLcy7Ehbgw50JciAtzLpxDxIU51y_mK8T1ZXFhzoW4EBfmXIgLcf23cy5idJojnZ7GAbjm5rt-lgPfPGYVydcmaTttAmPHB62TEuq75AH6eYA2gjTJB10UX50NeAHOWj6eClI5Z6UxMrQNfrroqwxaKxcth21g8IrV-vf16uwA9CW0_sur0fnrVgvqvX7ERY9EaZiArwbfKQ2AD7Qfrroscz1_n-O6x3L6N2NJEsPSmgq0kZxCn71GRB9HYe7YUecVSh-l1JoRvnDJ_laT4Wat3deXStOl0WXdWQ99v1H6FJd1vL2WJSaMw_SPLytvsJ2p8jd9KS2a-q0mROxaY5b4MdjId3oRdLIBf7YpFbJbt_L8pqzjCaj7vCUTpZvBqXVgidK5CVtBY6U_Y7yQ-xxMzH1jsImo6t_r6xPt06giI2Fa7XrU6Yis4kFXZCLFXByzat_piNjD3PuZiL6fWBTq97Ry9PsyGspJdz_Lu-cb8ZP6Q73eDvoA_y1ZEo752P-DADbuhsPaapYfYIZxlWqegvb2GTmk1K9ZHMJ8TWpuOoprR9mWyNv2nxMyWrtWe79WL2OfiiR8hXoeo06ZmfkRYo7dr_ErxmSq22c0hLm9ruELFoOcmOuM3j3Xmi_NJfaofabyg7CSh3USvEL9i4bLMI_q-bW_a1xU2jPcDHLuvOurCc62GWwWxmJjm33snGgdpZWKdw_n5cybLCKpNOx--xMJYu-tIIgAAA,,",
                           "n": "互刷互赞", "pi": pi, "pk": "7", "s": "9", "sk": sk, "ui": ui, "w": "19"}, "ev": 1}

    suc, r = send_加密发送_拼接提示(data_创建关卡, "创建关卡")
    if suc:
        suc1, json_object1 = send_加密发送_解密响应(data_发布关卡)
        if suc1:
            print("创建关卡成功")
            level_id = str(json_object1["i"])
            # 查找同作者的关卡
            data = {"req": "V734", "e": {"id": level_id, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
            suc2, json_object2 = send_加密发送_解密响应(data)
            if suc2:
                print("查询关卡成功")
                global c_庭院关卡号
                c_庭院关卡号.clear()
                # 解析响应
                for level in json_object2["ls"]:
                    c_庭院关卡号.append(level["i"])
                # 删除建立的临时关卡
                data_delete = {"req": "V727", "e": {"id": level_id, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                suc3, _ = send_加密发送_拼接提示(data_delete, f"删除建立的临时关卡")
                if suc3:
                    c_庭院关卡号.remove(level_id)
                print(f"您的账号中一共创建了 {len(c_庭院关卡号)} 个关卡")
                for index, value in enumerate(c_庭院关卡号, start=1):
                    print(f"第{index}个关卡号是 {value}")
                make_删除关卡()
            else:
                print("查询关卡失败")
        else:
            print("创建关卡失败")

def make_删除关卡():
    while True:
        print("输入0, 可以删除全部创建的关卡:")
        id_delete = input("请输入关卡号删除关卡, 按回车确定, 不输入直接按回车退出:")
        if not id_delete:
            break
        elif id_delete == "0":
            a_0 = input("你确定要删除所有创建的关卡吗???确定请输入1:")
            if a_0 == "1":
                for id_delete_level in c_庭院关卡号:
                    data = {"req": "V727", "e": {"id": id_delete_level, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                    send_加密发送_拼接提示(data, "删除关卡{}".format(id_delete_level))
            else:
                break
        else:
            data = {"req": "V727", "e": {"id": id_delete, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
            send_加密发送_拼接提示(data, "删除关卡{}".format(id_delete))

def make_追击分数():
    print("*****请注意, 分数超标被举报封号概不负责*****")
    print("每次修改分数需消耗5电池, 可修改不存在的关卡")
    print("输入对应的数字选择, 按回车确认, 不输入直接回车退出该函数")
    choice_0 = input("请输入选项, 1:修改普通关, 2:修改BOSS关:")
    if choice_0 == "1":
        l = input("您想修改第几关:")
        while int(l) < 1:
            l = input("输入无效, 请重新输入:")
        g = input("您想修改几辣椒:")
        s = input("您想要多少分, 不超过36000:")
        data = {"req": "V927", "e": {"fr": {"t": "1", "l": l, "g": g, "s": s, "r": "1", "b": "1.000000"}, "g": "1",
                                     "on": "ef647c8f138b4c8fae810004c3e40173", "pi": pi, "pr": {"pl": []}, "sk": sk,
                                     "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "修改第{}关{}辣椒{}分".format(l, g, s))
        input("按回车继续")
        return 0
    elif choice_0 == "2":
        l = input("您想修改第几关BOSS,请确保BOSS可打:")
        while int(l) < 1:
            l = input("输入无效, 请重新输入:")
        s = input("您想要多少分, 不超过22500:")
        data = {"req": "V927", "e": {"fr": {"t": "2", "l": l, "g": l, "s": s, "r": "1", "b": "2.000000"}, "g": "1",
                                     "on": "6f9f131ab599477da8bb99835ec39071", "pi": pi, "pr": {"pl": []}, "sk": sk,
                                     "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "修改僵王第{}关{}分".format(l, s))
        input("按回车继续")
        return 0
    else:
        return 1

def make_追击分数主程序():
    over = 0
    while over != 1:
        over = make_追击分数()

def make_庭院游玩币():
    import random
    for i in range(1, 11):
        data = {"req": "V735", "e": {"id": str(random.randint(100, 70000000)), "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "第{}次游玩庭院".format(i))

def make_追击币():
    data = CNNetwork.encrypt_dict({"req": "V927",
                                   "e": {"fr": {"t": "1", "l": "1", "g": "3", "s": "0", "r": "1", "b": "1.000000"},
                                         "g": "1", "on": "ef647c8f138b4c8fae810004c3e40173", "pi": pi, "pr": {"pl": []},
                                         "sk": sk, "ui": ui}, "ev": 1})
    global count_追击币
    r1 = None  # 函数内通用变量初始化

    def make_追击线程():
        nonlocal r1  # 声明函数内通用变量, 用于传递ip被锁信息
        suc, r1 = send_for_intent(data, "获得追击币")
        if suc:
            global count_追击币
            count_追击币 += 1
            print(f"已获得追击币{count_追击币 * 25}")

    print("刷追击币需要大量电池")
    a_目标追击币 = input("请输入你想要刷多少追击币:")
    while count_追击币 < int(a_目标追击币) / 25 - 1:
        threading.Thread(target=make_追击线程).start()  # 启动多线程
        if r1 == "ip被锁":  # 判断是否被锁
            time.sleep(0.6)
            print("ip好像被锁, 请开关飞行模式或者等待3分钟")
            print("正在暂停5分钟")
            time.sleep(301)
            r1 = None  # 初始化错误提示避免一直误判
        time.sleep(send_多线程延迟)  # 多线程延迟0.17s 拓维允许最低延迟
    time.sleep(0.6)  # 等待0.5s确保所有线程完成任务
    print(f"一共获得追击币{count_追击币 * 25}")
    count_追击币 = 0

def make_补签():
    for i in range(1, 32):
        data = {"req": "V389", "e": {"gt": "4", "hg": "1", "lc": "1", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "第{}次补签".format(i))

def make_签到():
        data = {"req": "V389", "e": {"gt": "4", "hg": "1", "lc": "1", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "每日签到成功")

def make_重置无尽商店():
    data = {"req":"V222","e":{"p":{"st":1,"rs":1},"pi":pi,"rv":"5","sk":sk,"t":"13","ui":ui},"ev":1}
    suc, _ = send_加密发送_拼接提示(data, "使用无尽币重置")
    return suc

def make_重置坠机商店():
    data = {"req":"V928","e":{"ad":"0","c":"0","pi":pi,"s":"1","sk":sk,"ui":ui},"ev":1}
    suc, _ = send_加密发送_拼接提示(data, "使用坠机币重置")
    return suc
       
def make_自动刷新无尽商店(use_diamond: bool):
    data_ad = {"req":"V222","e":{"p":{"st":1,"rs":2},"pi":pi,"rv":"5","sk":sk,"t":"13","ui":ui},"ev":1}
    suc, _ = send_加密发送_拼接提示(data_ad, "免费刷新无尽商店")
    if not suc:
            if use_diamond:
                return make_重置无尽商店()
            else:
                return False
    return True

def make_自动刷新坠机商店(use_diamond: bool):
    make_进入追击()
    data_ad = {"req":"V928","e":{"ad":"1","c":"0","pi":pi,"s":"1","sk":sk,"ui":ui},"ev":1}
    suc, _ = send_加密发送_拼接提示(data_ad, "免费刷新坠机商店")
    if not suc:
            if use_diamond:
                return make_重置坠机商店()
            else:
                return False
    return True

def make_全自动买材料():
    count = 0
    print("请输入想要购买多少次, 按回车继续")
    set_times = int(input("优先使用免费次数重置, 用完后将会消耗坠机币重置:"))
    make_坠机币()
    make_坠机币2()
    make_自动刷新坠机商店(True)
    while True:
        make_买神器材料(count + 1)
        count = count + 1
        if count == set_times:
            break
        make_坠机币()
        make_坠机币2()
        make_自动刷新坠机商店(True)
    print("自动购买神器材料完成, 共完成了{}次".format(count))
       
def make_全自动培养液():
    count = 0
    print("请输入想要刷新多少次, 按回车继续")
    set_times = int(input("优先使用免费次数重置, 用完后将会消耗无尽币重置:"))
    make_自动刷新无尽商店(True)
    while True:
        make_买培养液(count + 1)
        count = count + 1
        if count == set_times:
            break
        make_自动刷新无尽商店(True)
    print("自动购买培养液完成, 共完成了{}次".format(count))

def make_无尽商店购买():
    count = 0
    print("请输入想要购买多少次, 按回车继续")
    set_rounds = int(input("优先使用免费次数重置, 用完后将会消耗无尽币重置:"))
    while count < set_rounds:
        make_自动刷新无尽商店(True)
        print("请输入需要购买的物品代码（多个代码用空格隔开）:")
        codes = input().strip().split()
        for code in codes:
            item_name = "未知"
            if code in 植物碎片字典:
                item_name = 植物碎片字典[code]
            elif code in 植物装扮碎片字典:
                item_name = 植物装扮碎片字典[code]
            elif code in 道具字典:
                item_name = 道具字典[code]
            elif code in 碎片颜色字典:
                item_name = 碎片颜色字典[code]
            elif code in 碎片品质字典:
                item_name = 碎片品质字典[code]
            d = {"req":"V222","e":{"p":{"st":1,"id":code},"pi":pi,"rv":"5","sk":sk,"t":"14","ui":ui},"ev":1}
            send_加密发送_拼接提示(d, f"购买{item_name}")
        count += 1
        print(f"第 {count} 轮购买完成")
    print(f"共购买了 {count} 轮")

def make_家族():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        encrypt_data = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=encrypt_data.encode('utf-8'))
        if response.status_code != 200:
            print("获取失败")
            return
        decrypt_data = CNNetwork.decrypt(response.text)
        res = json.loads(decrypt_data)
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - (len(p_decode) % 4))
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
        家族列表 = p_json.get("sd", {}).get("pfi", [])
        if not 家族列表:
            print("未获取到家族信息")
            return
        selectable = {}
        print("请选择家族：")
        for idx, item in enumerate(家族列表, start=1):
            fi = str(item.get("pfi"))
            pf = item.get("pfbv")  
            if pf and len(pf) == 1:
                color = GREEN
            elif pf and len(pf) > 1:
                color = ORANGE
            else:
                color = WHITE
            status = "未激活" if not pf else ("只解锁了1个词条" if len(pf) == 1 else "全解锁")
            if fi in 家族字典:
                display = 家族字典[fi]
            else:
                display = fi
            print(f"{color}{idx}. {display} - {status}{RESET}")
            selectable[idx] = fi
        choice = input("输入序号选择家族: ").strip()
        if not choice.isdigit() or int(choice) not in selectable:
            print("选择无效")
            return
        chosen_fi = selectable[int(choice)]
        lv_input = input("请输入家族等级(lv): ").strip()
        if not lv_input.isdigit():
            print("等级输入无效")
            return
        selected_item = None
        for item in 家族列表:
            if str(item.get("pfi")) == chosen_fi:
                selected_item = item
                break
        if not selected_item:
            print("未找到对应家族数据")
            return
        attrs = selected_item.get("pfbv", [])
        if len(attrs) == 1:
            unlock_choice = input("该家族只解锁了1个词条，是否解锁二词条? (y/n): ").strip().lower()
            if unlock_choice == "y":
                data_unlock = {"req": "V325", "e": {"fi": chosen_fi, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                _, _ = send_加密发送_解密响应(data_unlock)
                print("二词条解锁请求已发送")
        l_val = ""
        if len(attrs) > 1:
            single_choice = input("是否希望单刷某个词条? (y/n): ").strip().lower()
            if single_choice == "y":
                print("当前已解锁词条及其当前属性值：")
                for idx, attr in enumerate(attrs, start=1):
                    pfbvt = attr.get("pfbvt", "未知")
                    desc = 属性字典.get(pfbvt, pfbvt)
                    current_value = attr.get("pfbv", 0) * 100
                    print(f"{idx}. {desc}: 当前值 {current_value:.2f}%")
                sel = input("输入序号选择需要锁定的词条: ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(attrs):
                    l_val = attrs[int(sel)-1].get("pfbm", "")
                else:
                    print("未选择单刷词条，采用默认整体刷新")
        while True:
            print("\n请选择刷新方式：")
            print("1. 免费刷新")
            print("2. 广告刷新")
            print("3. 钻石刷新")
            refresh_choice = input("输入对应数字: ").strip()
            if refresh_choice == "1":
                ad = "0"
                f = "1"
            elif refresh_choice == "2":
                ad = "1"
                f = "0"
            elif refresh_choice == "3":
                ad = "0"
                f = "0"
            else:
                print("刷新方式选择错误")
                continue
            def 刷新请求(ad, f, l_val):
                req_data = {
                    "req": "V326",
                    "e": {
                        "ad": ad,
                        "f": f,
                        "fi": chosen_fi,
                        "is": "0",
                        "l": l_val,
                        "lv": lv_input,
                        "pi": pi,
                        "sk": sk,
                        "ui": ui
                    },
                    "ev": 1
                }
                return send_加密发送_解密响应(req_data)[1]
            
            print("发起刷新请求……")
            resp = 刷新请求(ad, f, l_val)
            if not resp.get("fl"):
                print("刷新失败")
            else:
                current_data = None
                for fam in resp.get("fl", []):
                    if str(fam.get("fi")) == chosen_fi:
                        current_data = fam
                        break
                if not current_data:
                    print("未获取到刷新数据")
                else:
                    if chosen_fi in 家族字典:
                        family_display = 家族字典[chosen_fi]
                    else:
                        family_display = chosen_fi
                    print(f"\n家族: {family_display}")
                    print(f"等级: {current_data.get('l')}")
                    for c in current_data.get("c", []):
                        t = c.get("t", "未知")
                        t_display = 属性字典.get(t, t)
                        n = c.get("n", 0)
                        bt_val = c.get("bt")
                        if bt_val:
                            bt_display = 属性字典.get(bt_val, bt_val)
                        else:
                            bt_display = "未刷新"
                        bn = c.get("bn")
                        bn_disp = f"{bn*100:.2f}%" if bn not in (None, 0) else "未刷新"
                        print(f"属性: {t_display}, 当前值: {n*100:.2f}%, 刷新属性: {bt_display}, 刷新值: {bn_disp}")
                    p_info = resp.get("p", {})
                    diamonds = p_info.get("g1", "未知")
                    print(f"当前钻石: {diamonds}")
            save_choice = input("\n是否保存刷新结果? (y/n): ").strip().lower()
            if save_choice == "y":
                data_save = {"req": "V327", "e": {"fi": chosen_fi, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                _, _ = send_加密发送_解密响应(data_save)
                print("刷新结果已保存")
            next_step = input("是否继续刷新? (y/n): ").strip().lower()
            if next_step != "y":
                print("退出刷新流程")
                break

    except Exception as e:
        print(f"异常: {e}")

#===========================全自动家族======================
def make_全自动刷新家族():
    BLUE = Fore.BLUE
    RED = Fore.RED
    GREEN = Fore.GREEN
    WHITE = Fore.WHITE
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    RESET = Style.RESET_ALL
    def get_random_color():
        colors = [BLUE, RED, GREEN, WHITE, YELLOW, CYAN, MAGENTA]
        return random.choice(colors)
    属性映射表 = {
        "extra_sunmoney_50": f"{get_random_color()}额外产出50阳光{RESET}",
        "extra_sunmoney_25": f"{get_random_color()}额外产出25阳光{RESET}",
        "extra_hitpoints": f"{get_random_color()}生命值增加{RESET}",
        "extra_attack": f"{get_random_color()}攻击力增加{RESET}",
        "regeneration": f"{get_random_color()}每5秒恢复生命{RESET}",
        "lower_cost": f"{get_random_color()}阳光消耗降低{RESET}",
        "fast_plant": f"{get_random_color()}种植冷却缩短{RESET}",
        "improved_atk_rate": f"{get_random_color()}攻击速度增加{RESET}",
        "improved_explode_damage": f"{get_random_color()}爆炸伤害增加{RESET}",
        "improved_flame_damage": f"{get_random_color()}火焰伤害增加{RESET}",
        "improved_cold_damage": f"{get_random_color()}冰冻伤害增加{RESET}",
        "improved_lightning_damage": f"{get_random_color()}闪电伤害增加{RESET}",
        "invincible": f"{get_random_color()}无敌3秒概率{RESET}",
        "ghost": f"{get_random_color()}灵魂状态概率{RESET}",
        "plant_sun_refund": f"{get_random_color()}返还阳光概率{RESET}",
        "extra_defend": f"{get_random_color()}防御力增加{RESET}",
        "extra_melee_attack": f"{get_random_color()}近战伤害增加{RESET}",
        "improved_sunproduce_rate": f"{get_random_color()}生产速度增加{RESET}"
    }
    家族映射表 = {
        "50001": f"{get_random_color()}新人组{RESET}",
        "50002": f"{get_random_color()}光芒万丈{RESET}",
        "50003": f"{get_random_color()}不动如山{RESET}",
        "50004": f"{get_random_color()}真能打{RESET}",
        "50005": f"{get_random_color()}我要打十个{RESET}",
        "50006": f"{get_random_color()}火力全开{RESET}",
        "50007": f"{get_random_color()}冰力四射{RESET}",
        "50008": f"{get_random_color()}雷霆万钧{RESET}",
        "50009": f"{get_random_color()}能量武器{RESET}",
        "50010": f"{get_random_color()}精英豌豆{RESET}",
        "50011": f"{get_random_color()}军火库{RESET}",
        "50012": f"{get_random_color()}三分王{RESET}",
        "50013": f"{get_random_color()}神射手{RESET}",
        "50014": f"{get_random_color()}百步穿僵{RESET}",
        "50015": f"{get_random_color()}人多力量大{RESET}",
        "50016": f"{get_random_color()}踩僵尸的蘑菇{RESET}",
        "50017": f"{get_random_color()}暗影家族{RESET}",
        "50018": f"{get_random_color()}环保卫士{RESET}",
        "50019": f"{get_random_color()}文艺青年{RESET}",
        "50020": f"{get_random_color()}忍者小队{RESET}",
        "50021": f"{get_random_color()}大厨组合{RESET}",
        "50022": f"{get_random_color()}摧枯拉朽{RESET}",
        "50023": f"{get_random_color()}坚固防线{RESET}",
        "50024": f"{get_random_color()}控场大师{RESET}",
        "50025": f"{get_random_color()}魔法大师{RESET}",
        "50026": f"{get_random_color()}枝繁叶茂{RESET}",
        "50027": f"{get_random_color()}十二生肖{RESET}",
        "50028": f"{get_random_color()}繁花似锦{RESET}",
        "50029": f"{get_random_color()}打飞他们{RESET}",
        "50030": f"{get_random_color()}十万伏特{RESET}",
        "50031": f"{get_random_color()}动物世界{RESET}",
        "50032": f"{get_random_color()}炸个痛快{RESET}",
        "50033": f"{get_random_color()}小心脚下{RESET}",
        "50034": f"{get_random_color()}惊声尖笑{RESET}",
        "50035": f"{get_random_color()}运动健将{RESET}",
        "50036": f"{get_random_color()}不如跳舞{RESET}",
        "50037": f"{get_random_color()}头有点晕{RESET}",
        "50038": f"{get_random_color()}酸甜苦辣{RESET}",
        "50039": f"{get_random_color()}武林对决{RESET}",
        "50040": f"{get_random_color()}地爆天星{RESET}",
        "50041": f"{get_random_color()}光暗交织{RESET}",
        "50042": f"{get_random_color()}亿点控制{RESET}",
        "50043": f"{get_random_color()}冰与火{RESET}",
        "50044": f"{get_random_color()}未来科技{RESET}",
        "50045": f"{get_random_color()}花开富贵{RESET}",
        "50046": f"{get_random_color()}火力压制{RESET}",
        "50047": f"{get_random_color()}群卜荟萃{RESET}"
    }
    print(f"{get_random_color()}请选择要刷新的家族：{RESET}")
    for index, (fid, name) in enumerate(家族映射表.items(), start=1):
        print(f"{get_random_color()}{index}. {name} (ID: {fid}){RESET}")
    家族序号 = input(f"{get_random_color()}请输入家族序号：{RESET}")
    chosen_family_id = list(家族映射表.keys())[int(家族序号) - 1]

    刷级 = input(f"{get_random_color()}请输入要刷的等级：{RESET}")
    print(f"{get_random_color()}请选择要刷的属性：{RESET}")
    属性列表 = list(属性映射表.items())
    for i, (code, name) in enumerate(属性列表, start=1):
        print(f"{get_random_color()}{i}. {name} ({code}){RESET}")
    num = int(input(f"{get_random_color()}请输入选择的序号：{RESET}"))
    chosen_attr = 属性列表[num - 1][0]

    print(f"{get_random_color()}开始全自动刷新家族（家族ID:{chosen_family_id}），刷等级 {刷级}，目标属性：{属性映射表.get(chosen_attr)}{RESET}")
    while True:
        家族请求 = {
            "req": "V326",
            "e": {
                "ad": "0",
                "f": "0",
                "fi": chosen_family_id,
                "l": 刷级,
                "lv": 刷级,
                "pi": pi,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        suc, r = send_加密发送_解密响应(家族请求)
        if not suc or not isinstance(r, dict):
            print(f"{get_random_color()}刷新家族失败{RESET}")
            time.sleep(1)
            continue
        try:
            家族信息 = r['fl']
            玩家信息 = r['p']
            属性_found = False
            for 家族项 in 家族信息:
                if 家族项['fi'] == chosen_family_id:
                    for 属性 in 家族项['c']:
                        if 'bt' in 属性 and 'bn' in 属性:
                            当前值 = 属性['bn'] * 100
                            属性代码 = 属性['bt']
                            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
                            cleaned_code = ansi_escape.sub('', 属性代码)
                            cleaned_chosen = ansi_escape.sub('', chosen_attr)
                            属性中文 = 属性映射表.get(cleaned_code, cleaned_code)
                            if cleaned_code == cleaned_chosen:
                                print(f"{get_random_color()} -新- {属性中文}: {当前值:.2f}%{RESET}")
                                属性_found = True
                            else:
                                print(f"{get_random_color()} - {属性中文}: {当前值:.2f}%{RESET}")
                    print(f"{get_random_color()}当前钻石数量💎: {玩家信息['fg']}{RESET}")
            if 属性_found:
                print(f"{get_random_color()}你要刷的属性出现了，立即停止刷新。{RESET}")
                save_choice = input(f"{get_random_color()}是否保存属性？(y/n): {RESET}")
                if save_choice.lower() == "y":
                    属性保存 = {
                        "req": "V327",
                        "e": {
                            "fi": chosen_family_id,
                            "pi": pi,
                            "sk": sk,
                            "ui": ui
                        },
                        "ev": 1
                    }
                    send_加密发送_拼接提示(属性保存, f"{get_random_color()}属性保存{RESET}")
                return
            else:
                print(f"{get_random_color()}没刷到新属性。{RESET}")
        except KeyError as e:
            print(f"{get_random_color()}解析家族信息失败，错误: {e}{RESET}")
        time.sleep(0.5)

def make_买培养液(count_买培养液次数):
    count = 0
    d={"req":"V222","e":{"p":{"st":1,"id":23011},"pi":pi,"rv":"5","sk":sk,"t":"14","ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买橙培养液")
    d={"req":"V222","e":{"p":{"st":1,"id":23010},"pi":pi,"rv":"5","sk":sk,"t":"14","ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买紫培养液")
    d={"req":"V222","e":{"p":{"st":1,"id":23009},"pi":pi,"rv":"5","sk":sk,"t":"14","ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买蓝培养液")
    d={"req":"V222","e":{"p":{"st":1,"id":23008},"pi":pi,"rv":"5","sk":sk,"t":"14","ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买绿培养液")
    d={"req":"V222","e":{"p":{"st":1,"id":23007},"pi":pi,"rv":"5","sk":sk,"t":"14","ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买白培养液")

def make_买神器材料(count_买神器材料次数):
    count = 0
    d={"req":"V392","e":{"ci":"500","gi":"23112","mi":"23093","pi":pi,"q":"10","si":"8","sk":sk,"ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买10神器罐子")
    d={"req":"V392","e":{"ci":"1500","gi":"23113","mi":"23093","pi":pi,"q":"1","si":"8","sk":sk,"ui":ui},"ev":1}
    send_加密发送_拼接提示(d,"购买1神器魔方")

def make_普通挂件():
    global uk
    make_ukugd()
    items_list = [
        {"i": 22001, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22002, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22003, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22004, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22005, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22006, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22007, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22008, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22009, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22010, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22011, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22012, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22013, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22014, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22015, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22016, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22017, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22018, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22019, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22020, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22021, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22022, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22023, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22024, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22025, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22026, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22027, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22028, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22029, "q": 30, "f": "safe20_hard_level_reward"},
        {"i": 22030, "q": 30, "f": "safe20_hard_level_reward"},
    ]
    print("可领取的普通挂件碎片：")
    LEFT_WIDTH = 20  
    total = len(items_list)
    for i in range(0, total, 3):
        line_parts = []
        for j in range(3):
            idx = i + j
            if idx < total:
                item = items_list[idx]
                code = str(item["i"])
                name = 道具字典.get(code, code)
                seq = f"{idx+1:2d}. {name}"
                line_parts.append(ljust_visual(seq, LEFT_WIDTH))
            else:
                line_parts.append("")
        print("".join(line_parts))
    
    choice = input("请输入选择项编号（空格分隔，或者输入all全选，直接回车退出）：").strip()
    if not choice:
        return
    new_items = []
    if choice.lower() == "all":
        selected_indices = list(range(1, total+1))
        qty_input = input("请输入领取数量（全部都使用相同数量，直接回车退出）：").strip()
        if not qty_input:
            return
        try:
            qty = int(qty_input)
        except:
            print("数量输入错误！")
            return
        for idx in selected_indices:
            orig_item = items_list[idx-1]
            new_items.append({"i": orig_item["i"], "q": qty, "f": orig_item["f"]})
    else:
        selected_indices = []
        for part in choice.split():
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= total:
                    selected_indices.append(idx)
        if not selected_indices:
            print("没有选择有效项！")
            return
        qty_inputs = input("请输入各选项对应的领取数量（空格分隔，直接回车退出）：").strip().split()
        if not qty_inputs:
            return
        if len(qty_inputs) != len(selected_indices):
            print("数量个数与选择项数量不匹配！")
            return
        for idx, qty_str in zip(selected_indices, qty_inputs):
            try:
                qty = int(qty_str)
            except:
                print("数量输入错误！")
                return
            orig_item = items_list[idx - 1]
            new_items.append({"i": orig_item["i"], "q": qty, "f": orig_item["f"]})
    
    data = {"req": "V302","e": {"nfc": "1","o": new_items,"pi": pi,"sk": sk,"ui": ui,"uk": uk + 1},"ev": 1}
    send_加密发送_拼接提示(data, "领取普通挂件碎片")
data_o_302钻石 = []
for _ in range(30):
    data_o_302钻石.append({"i": 3008, "q": 50})


def make_领取302钻石():
    global uk
    make_ukugd()
    data_302钻石 = {"req": "V302", "e": {"nfc": "0", "o": data_o_302钻石, "pi": pi, "sk": sk, "ui": ui, "uk": uk + 1},
                    "ev": 1}
    uk + 1
    send_加密发送_拼接提示(data_302钻石, "世界困难关卡钻石")

def make_21亿负钻石():
    data = {"req":"V302","e":{"nfc":"1","o":[{"i":3008,"q":-2147483647,"f":"safe20_hard_level_reward"}],"pi":pi,"sk":sk,"ui":ui,"uk":"-2147483647"},"ev":1}
    send_加密发送_拼接提示(data, "21亿负钻石爆炸")


def make_领取神器():
    data = {"req": "V900",
            "e": {"pi": pi, "pl": [{"i": 60003, "q": 1}, {"i": 60004, "q": 1}, {"i": 60006, "q": 1}], "sk": sk,
                  "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(data, "神器领取")


def make_每周神秘水晶2w():
    data = {"req": "V900", "e": {"pi": pi, "pl": [{"i": 23097, "q": 20000}], "sk": sk, "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(data, "每周2w神秘水晶领取")


def make_每日神秘水晶():
    data = {"req": "V765", "e": {"id": "3", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    for i in range(1, 4):
        send_加密发送_拼接提示(data, "第{}次领取神秘水晶1000".format(i))


def make_每日联赛钥匙():
    data_点击联赛 = {"req": "V303",
                     "e": {"al": [{"id": 10704, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                           "pack": "com.popcap.pvz2cthd4399", "pi": pi, "sk": sk, "ui": ui, "v": newest_version},
                     "ev": 1}
    data = {"req": "V765", "e": {"id": "4", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(data_点击联赛, "点击超z联赛")
    for i in range(1, 2):
        send_加密发送_拼接提示(data, "领取超z联赛钥匙{}个".format(i))


def make_回忆成就():
    x = 0  # 初始化成功次数
    for i in range(1, 31):
        data = {"req": "V976", "e": {"ctp": "1", "i": str(1000 + i), "pi": pi, "sk": sk, "tp": "10839", "ui": ui},
                "ev": 1}
        suc, _ = send_加密发送_拼接提示(data, "领取回忆成就{}".format(1000 + i))
        if suc:
            x += 1
            if x == 12:
                print("回忆成就领取完毕")
                break


def make_回忆奖励():
    x = 0  # 初始化成功次数
    for i in range(1, 11):
        data = {"req": "V976", "e": {"ctp": "0", "i": str(i), "pi": pi, "sk": sk, "tp": "10839", "ui": ui}, "ev": 1}
        suc, _ = send_加密发送_拼接提示(data, "领取回忆奖励{}".format(i))
        if suc:
            x += 1
            if x == 5:
                print("回忆奖励领取完毕")
                break


def make_神秘宝藏():
    data_进入宝藏 = {"req": "V303",
                     "e": {"al": [{"id": 10749, "abi": 0, "type": 1, "config_version": 1}], "ci": "93", "cs": "0",
                           "pack": "com.popcap.pvz2cthd4399", "pi": pi, "sk": sk, "ui": ui, "v": newest_version},
                     "ev": 1}
    send_加密发送(data_进入宝藏)
    data_神秘宝藏 = {"req": "V795",
                     "e": {"ai": "10749", "g": "1", "pi": pi, "s": "250", "sk": sk, "ti": "1001", "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(data_神秘宝藏, "领取神秘宝藏经验")
    for i in range(6):
        data = {"req": "V792", "e": {"ai": "10749", "i": i, "pi": pi, "sk": sk, "t": "1", "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "领取神秘宝藏奖励{}".format(i + 1))

#===========================探险======================
def make_进入探险():
    global pi, sk, ui   
    d_={"req":"V303","e":{"al":[{"id":10808,"abi":0,"type":1,"config_version":1}],"ci":"91","cs":"0","pack":"com.popcap.pvz2cthd4399","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d_,"进入探险活动")
def remove_ansi(s):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', s)

def print_grouped(items, group_size, col_width=25):
    for i in range(0, len(items), group_size):
        group = items[i:i+group_size]
        line = ""
        for it in group:
            line += ljust_visual(it, col_width) + "  "  
        print(line.rstrip())

def display_width(s):
    s_clean = remove_ansi(s)
    width = 0
    for char in s_clean:
        if '\u4e00' <= char <= '\u9fff':
            width += 2
        else:
            width += 1
    return width

def ljust_visual(s, width):
    current = display_width(s)
    if current >= width:
        return s
    return s + " " * (width - current)

def make_探险():
    global pi, sk, ui
    tasks = {
        "豌豆射手": 10427,
        "卷心菜投手": 10428,
        "向日葵": 10429,
        "玉米投手": 10430,
        "地刺": 10431,
        "弹簧豆": 10432,
        "双向射手": 10433,
        "巴豆": 10434,
        "闪电芦苇": 10435,
        "火葫芦": 10436,
        "白萝卜": 10437,
        "土豆地雷": 10438,
        "坚果": 10439,
        "冰冻生菜": 10440,
        "大喷菇": 10441,
        "磁力菇": 10442,
        "缠绕水草": 10443,
        "鳄梨": 10444,
        "火焰豌豆": 10445,
        "旋转芜箐": 10446,
        "枇杷": 10447,
        "电离红掌": 10448,
        "红针花": 10449,
        "菠萝蜜": 10450,
        "芹菜": 10451,
        "复活萝卜": 10452,
        "原始豌豆": 10453,
        "香水蘑菇": 10454,
        "毒影菇": 10457,
        "月光花": 10458,
        "番莲工程师": 10459,
        "莲藕射手": 10460,
        "冬瓜": 10461,
        "芦荟医师": 10462,
        "石斛防风草": 10463,
        "千金藤": 10464
    }
    wi_to_name = {str(v): name for name, v in tasks.items()}
    def get_name(code):
        return wi_to_name.get(str(code), str(code))
    
    print("操作模式：")
    print(" 1: 终止探险并执行后续操作（可选择收取碎片）")
    print(" 2: 正常探险")
    op = input("请输入选项编号（直接回车退出）：").strip()
    if not op:
        return
    try:
        op = int(op)
    except ValueError:
        print("输入错误")
        return
    if op not in (1, 2):
        print("输入错误")
        return

    if op == 1:
        data_279 = {"req": "V279", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        suc_279, res_279 = send_加密发送_解密响应(data_279)
        exploring_plants = []
        if suc_279:
            e_list = res_279.get("e")
            if e_list:
                for item in e_list:
                    code = item.get("wi", "")
                    if not code:
                        print("警告：探险项目缺少wi，跳过该项目")
                        continue
                    s_val = item.get("s", None)
                    try:
                        s_val_int = int(s_val) if s_val is not None else None
                    except Exception as e:
                        print(f"错误：解析状态值 {s_val} 出错，跳过该项目")
                        continue
                    name = get_name(code)
                    if s_val_int is None:
                        status_str = "未知"
                    elif s_val_int == 1:
                        status_str = "已领取"
                    elif s_val_int == 2:
                        status_str = "进行中"
                    elif s_val_int == 3:
                        status_str = "结束未收获"
                    else:
                        status_str = f"状态{s_val_int}"
                    exploring_plants.append((code, name, s_val_int))
                    print(f"    {name} 状态：{status_str}")
            else:
                print("无正在探险植物")
                return
        else:
            print("无正在探险植物")
            return
        if not exploring_plants:
            print("没有可用的探险项目")
            return
        print("请选择操作：")
        print(" 1: 终止探险")
        print(" 2: 收取探险碎片")
        sub_op = input("请输入选项编号（直接回车退出）：").strip()
        if not sub_op:
            return
        try:
            sub_op = int(sub_op)
        except ValueError:
            print("输入错误")
            return
        if sub_op not in (1, 2):
            print("输入错误")
            return

        if sub_op == 1:
            print("请选择要终止探险的植物：")
            for idx, (code, name, s_val_int) in enumerate(exploring_plants, start=1):
                if s_val_int is None:
                    status_str = "未知"
                elif s_val_int == 1:
                    status_str = "已领取"
                elif s_val_int == 2:
                    status_str = "进行中"
                elif s_val_int == 3:
                    status_str = "结束未收获"
                else:
                    status_str = f"状态{s_val_int}"
                print(f" {idx}: {name} (状态：{status_str})")
            cancel_choice = input("请输入终止的序号（直接回车取消）：").strip()
            if not cancel_choice:
                return
            try:
                cancel_idx = int(cancel_choice)
            except ValueError:
                print("输入错误")
                return
            if not (1 <= cancel_idx <= len(exploring_plants)):
                print("输入错误")
                return
            cancel_code = exploring_plants[cancel_idx-1][0]
            data_终止探险 = {"req": "V282","e": {"f": "0", "pi": pi, "sk": sk, "ui": ui,"wi": int(cancel_code) if str(cancel_code).isdigit() else str(cancel_code)},"ev": 1}
            send_加密发送_拼接提示(data_终止探险, "终止探险")
        elif sub_op == 2:
            print("请选择要收取碎片的植物，多个编号以空格分隔（直接回车退出）：")
            for idx, (code, name, s_val_int) in enumerate(exploring_plants, start=1):
                if s_val_int is None:
                    status_str = "未知"
                elif s_val_int == 1:
                    status_str = "已领取"
                elif s_val_int == 2:
                    status_str = "进行中"
                elif s_val_int == 3:
                    status_str = "结束未收获"
                else:
                    status_str = f"状态{s_val_int}"
                print(f" {idx}: {name} (状态：{status_str})")
            collect_choice = input("请输入序号：").strip()
            if not collect_choice:
                return
            try:
                indices = [int(x) for x in collect_choice.split() if x]
            except ValueError:
                print("输入错误")
                return
            for idx in indices:
                if not (1 <= idx <= len(exploring_plants)):
                    print(f"索引 {idx} 输入错误，跳过")
                    continue
                collect_code = exploring_plants[idx-1][0]
                data_收取碎片 = {"req": "V283","e": {"ad": "0","is": "0","pi": pi,"sk": sk,"ui": ui,"wi": int(collect_code) if str(collect_code).isdigit() else str(collect_code)},"ev": 1}
                send_加密发送_拼接提示(data_收取碎片, f"收取 {get_name(collect_code)} 的碎片")
    elif op == 2:
        separator = "=" * 60
        print(separator)
        LEFT_WIDTH = 20
        print(separator)
        print(" q: 返回主菜单")
        items = list(tasks.items())
        for i in range(0, len(items), 3):
            columns = []
            for j in range(3):
                if i+j < len(items):
                    name, wi_val = items[i+j]
                    seq = f"{i+j+1:2d}: {name}"
                    columns.append(ljust_visual(seq, LEFT_WIDTH))
                else:
                    columns.append("")
            print("".join(columns))
        print(separator)
        while True:
            choice = input("请输入选项编号（q返回主菜单）：").strip()
            if choice == "q":
                print("返回主菜单")
                return
            if not choice:
                print("请输入有效的数字")
                continue
            try:
                d = int(choice)
            except ValueError:
                print("输入错误")
                continue
            if d < 1 or d > len(items):
                print("输入错误")
                continue
            task_name, wi = items[d-1]
            break

        x = 400
        count = 0
        data_看广告翻倍 = {"req": "V282","e": {"f": "5", "pi": pi, "sk": sk, "ui": ui, "wi": wi},"ev": 1}
        data_看广告完成 = {"req": "V283","e": {"ad": "1", "pi": pi, "sk": sk, "ui": ui, "wi": wi},"ev": 1}
        data_看广告增加次数 = {"req": "V282","e": {"f": "7", "pi": pi, "sk": sk, "ui": ui, "wi": wi},"ev": 1}
        data_终止探险 = {"req": "V282","e": {"f": "0", "pi": pi, "sk": sk, "ui": ui, "wi": wi},"ev": 1}
        send_加密发送_拼接提示(data_看广告增加次数, "看广告增加次数")
        groupA = {"原始豌豆", "芦荟医师", "番莲工程师", "千金藤", "毒影菇", "旋转芜箐", "红针花", "火焰豌豆", "大喷菇", "闪电芦箇"}
        groupB = {"豌豆射手", "卷心菜投手", "向日葵", "地刺", "弹簧豆", "双向射手", "白萝卜", "土豆地雷", "坚果",
                  "冰冻生菜", "枇杷", "菠萝蜜", "复活萝卜", "香水蘑菇", "月光花", "莲藕射手", "冬瓜", "石斛防风草"}
        while True:
            data_原始豌豆 = {"req": "V281","e": {"ic": "0", "pi": pi, "pl": [x, x+1, x+2, x+3, x+4],"sk": sk, "ui": ui, "wi": wi},"ev": 1}
            suc, res = send_加密发送_解密响应(data_原始豌豆)
            if not suc:
                print("探险次数已用完")
                print(f"探险完成，一共获得碎片{count}片")
                return
            try:
                data_碎片数 = res["e"][0]["b"]
            except Exception as e:
                print("解析探险响应错误")
                continue

            if task_name in groupA:
                if data_碎片数 == 2:
                    x += 5
                    print("恭喜本次探险获得2个植物碎片, 正在广告翻倍")
                    suc1, res1 = send_加密发送_拼接提示(data_看广告翻倍, "看广告翻倍")
                    if suc1:
                        count += 4
                        send_加密发送_拼接提示(data_看广告完成, "获取碎片4个")
                    else:
                        count += 2
                        send_加密发送_拼接提示(data_看广告完成, "获取碎片2个")
                elif data_碎片数 == 1:
                    print("本次探险仅获得1个碎片，正在终止探险")
                    send_加密发送_拼接提示(data_终止探险, "终止探险")
            elif task_name in groupB:
                if data_碎片数 == 1:
                    x += 5
                    print("恭喜本次探险获得1个植物碎片, 正在广告翻倍")
                    suc1, res1 = send_加密发送_拼接提示(data_看广告翻倍, "看广告翻倍")
                    if suc1:
                        count += 2
                        send_加密发送_拼接提示(data_看广告完成, "获取碎片2个")
                    else:
                        send_加密发送_拼接提示(data_看广告完成, "获取碎片0个")
            else:
                x += 5
                suc1, res1 = send_加密发送_拼接提示(data_看广告翻倍, "看广告翻倍")
                if suc1:
                    count += 2
                    send_加密发送_拼接提示(data_看广告完成, "获取碎片2个")
                else:
                    send_加密发送_拼接提示(data_看广告完成, "获取碎片0个")
def make_rand_court_level():
    zombies = ["heian_onmyoji", "explorer", "fairy_tale_knight", "fairy_tale_armed_gargantuar", "eighties_boombox",
               "heian_sushi", "lostcity_excavator", "fairy_tale_witch", "modern_allstar", "lostcity_guide",
               "childrensday_gargantuar", "children_toycar", "heian_gargantuar", "heian_hanabi", "heian_ninja",
               "heian_akinndo", "renai_perfumer", "renai_gliding", "renai_gargantuar", "steam_coal_miner",
               "steam_stove", "steam_gentleman", "steam_gargantuar", "modern_balloon", "newspaper_veteran",
               "explosion_proof", "modern_miner", "modern_solar_truck", "tutorial_gargantuar", "lostcity_doctor",
               "lostcity_gargantuar", "lostcity_crystalskull", "iceage_gargantuar", "iceage_hunter", "iceage_chief",
               "iceage_weaselhoarder", "dino_gargantuar", "dino_stealegg", "beach_fisherman", "beach_octopus",
               "beach_surfer", "beach_gargantuar", "beach_shell", "dark_wizard", "dark_juggler", "dark_king",
               "dark_archmage", "dark_rogue", "dark_imp_dragon", "football_mech", "disco_mech", "mech_cone",
               "future_protector", "future_gargantuar", "kongfu_qigong", "kongfu_monk_drink", "kongfu_monk_torch",
               "kongfu_gong", "kongfu_agile_bronze", "kongfu_magic_bronze", "kongfu_monk_nunchaku", "piano",
               "chicken_farmer", "west_bull", "cannon"] + ["fairy_tale_knight"] * 20

    portal_worlds = ["egypt", "pirate", "west", "future", "lostcity", "eighties", "dark", "beach", "dino", "iceage"]

    def get_random_wave():
        return {"EventType": 0, "Zombies": [
            {"ZombieType": random.choice(zombies), "ZombiePlaceRow": random.randint(0, 4),
             "Level": random.randint(1, 10)} for _ in range(random.randint(20, 100))],
                "AdditionalPlantfood": random.choice([0, 1]), "Event": {"SandStorm": {"ColumnEnd": 7, "ColumnStart": 1,
                                                                                      "Zombies": [random.choice(zombies)
                                                                                                  for _ in range(
                                                                                              random.randint(1, 20))],
                                                                                      "Type": random.choice([0, 1])},
                                                                        "SpiderRain": {"ColumnEnd": 7, "ColumnStart": 1,
                                                                                       "SpiderCount": random.randint(10,
                                                                                                                     100),
                                                                                       "SpiderZombieName": ""},
                                                                        "Portal": {"PortalColumn": random.randint(1, 7),
                                                                                   "PortalRow": random.randint(0, 4),
                                                                                   "PortalType": random.choice(
                                                                                       portal_worlds)},
                                                                        "DinoRun": {"DinoRow": -1, "TimeInterval": 0.0},
                                                                        "RaidingParty": {
                                                                            "SwashbucklerCount": random.randint(10,
                                                                                                                100)},
                                                                        "FrostWind": {"Winds": []},
                                                                        "ParachuteRain": {"ColumnEnd": 7},
                                                                        "BlackHole": {"ColNumPlantIsDragged": -1}}}

    return json.dumps({"d": {"cld": {"World": "beach", "LevelID": "7ad3b8b21d5efc13d2e0390dccdeab44",
                                     "LevelParams": {"Title": "", "Description": "", "LevelNumber": 0,
                                                     "StartingSun": 30000,
                                                     "WaveData": {"SpawnColEnd": 0, "SpawnColStart": 0,
                                                                  "WaveSpendingPointIncrement": 0,
                                                                  "WaveSpendingPoints": 0,
                                                                  "Waves": [get_random_wave() for _ in range(10)]},
                                                     "SeedBankData": {"BlackList": [], "PresetList": [], "Type": 0,
                                                                      "ConveyorList": [], "GlobalLevel": 5},
                                                     "Challenge": {"Description": "", "DescriptiveName": "",
                                                                   "ChallengeData": {
                                                                       "LastStand": {"StartingPlantfood": -1,
                                                                                     "StartingSun": 0}, "Molds": {
                                                                           "MoldGrids": [[0, 0, 0, 0, 0, 0, 0, 0, 0],
                                                                                         [0, 0, 0, 0, 0, 0, 0, 0, 0],
                                                                                         [0, 0, 0, 0, 0, 0, 0, 0, 0],
                                                                                         [0, 0, 0, 0, 0, 0, 0, 0, 0],
                                                                                         [0, 0, 0, 0, 0, 0, 0, 0, 0]]},
                                                                       "StatueMaze": {"SetInfos": []},
                                                                       "EvilDave": {"StartingSun": 0,
                                                                                    "PlantDistance": 0.0,
                                                                                    "PlantEntries": [],
                                                                                    "ZombieInfos": ["", "", "", "", "",
                                                                                                    "", "", ""]},
                                                                       "TowerDefend": {"PresetPlantList": [],
                                                                                       "TreeList": [],
                                                                                       "WaveData": {"Waves": []},
                                                                                       "Roads": []},
                                                                       "SingleHanded": {"StartingPlantType": "",
                                                                                        "WaveData": {"Waves": []},
                                                                                        "PlantInfos": []},
                                                                       "VaseBreaker": {"MinColumnIndex": -1,
                                                                                       "MaxColumnIndex": -1,
                                                                                       "VaseInfos": []}}},
                                                     "Elements": {"PlantInfos": [], "GridItemInfos": [],
                                                                  "ZombieInfos": [],
                                                                  "RailInfo": {"RailcartType": "railcart_cowboy",
                                                                               "RailCartInfos": [], "RailInfos": []},
                                                                  "PowerTileInfos": []},
                                                     "Encourage": {"IsEncourage": False, "BuySunmoney": True,
                                                                   "BuyPlantfood": True, "BuyMower": True}},
                                     "NetworkLevelID": 0,
                                     "NetworkLevelName": "\u00e9\u0080\u009f\u00e5\u0088\u00b7\u00e4\u00ba\u0092\u00e8\u00b5\u009e",
                                     "NetworkWorldType": 7, "NetworkLevelMode": 0, "NetworkEnableDownload": True,
                                     "NetworkAuthorName": "nope", "NetworkAuthorHeadshotID": 0,
                                     "NetworkUploadedTime": "", "NetworkUpdatedTime": "", "LevelIndex": 0,
                                     "HasFinishedLevel": True, "HasUploaded": False, "LocalUpdatedTime": time.time(),
                                     "PlayTime": random.uniform(20.0, 1000.0)}}}, separators=(",", ":"))


def b64_gzip_b64_encode(input_text: str):
    b64_1 = base64.urlsafe_b64encode(input_text.encode("utf-8")).decode("utf-8").replace("=", ",")
    gzip_1 = gzip.compress(b64_1.encode("utf-8"), compresslevel=9)
    b64_2 = base64.urlsafe_b64encode(gzip_1).decode("utf-8").replace("=", ",")
    return b64_2


def make_随机庭院关():
    data_创建关卡 = {"req": "V723",
                     "e": {"c": "100", "f": "0", "k": "0", "pi": pi, "pk": "0,1,2,3,4,5,6,7", "s": "0", "sk": sk,
                           "t": "2", "ui": ui, "w": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19"}, "ev": 1}

    rand_level = make_rand_court_level()

    data_发布关卡 = {"req": "V720", "e": {"checksum": hashlib.sha256(rand_level.encode("utf-8")).hexdigest(),
                                          "ci": "7ad3b8b21d5efc13d2e0390dccdeab44", "dl": "1", "id": "0",
                                          "lvd": b64_gzip_b64_encode(rand_level), "n": "速刷互赞", "pi": pi, "pk": "0",
                                          "s": "0", "sk": sk, "ui": ui, "w": "0"}, "ev": 1}

    suc, r = send_加密发送_拼接提示(data_创建关卡, "创建关卡")
    if suc:
        suc1, json_object = send_加密发送_解密响应(data_发布关卡)
        if suc1:
            print("发布关卡成功, id为{}".format(json_object["i"]))
        else:
            print("创建关卡失败")


def make_潘妮追击指南():
    data_潘妮追击指南 = {"req": "V795",
                         "e": {"ai": "10803", "g": "1", "pi": pi, "s": "300", "sk": sk, "ti": 1001, "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(data_潘妮追击指南, "领取潘妮追击指南经验")
    for i in range(7):
        data ={"req":"V792","e":{"ai":"10803","i":i,"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "领取潘妮追击指南奖励第{}次".format(i + 1))


def make_坠机币():
    make_进入追击()
    for i in range(1,81):
        def make_坠机币线程():
            data = {"req":"V927","e":{"fr":{"t":"1","l":"1","g":"3","s":"0","r":"1","b":"1.000000"},"g":"1","on":"bc6389f5c2db457da14e0e59549b3dcf","pi":pi,"pr":{"pl":[]},"sk":sk,"ui":ui},"ev":1}
            send_加密发送_拼接提示(data, "获得坠机币25第{}次".format(i))
        threading.Thread(target=make_坠机币线程).start()
        time.sleep(send_多线程延迟)



def make_坠机币2():
    make_进入追击()
    for i in range(1,3):
        data = {"req":"V927","e":{"fr":{"t":"1","l":"1","g":"2","s":"0","r":"1","b":"1.000000"},"g":"1","on":"bc6389f5c2db457da14e0e59549b3dcf","pi":pi,"pr":{"pl":[]},"sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data, "获得坠机币15第{}次".format(i))



def make_自动联赛():
    make_每日联赛钥匙()
    data_匹配 = {"req":"V380","e":{"pi":pi,"sk":sk,"ui":ui},"ev":1}
    data_领取连胜奖励 = {"req":"V381","e":{"cp":"1564","lfs":"84660","pi":pi,"pr":{"pl":[]},"r":"MDAwMDA0NzgwTS4uLi5FOC4yLi5nLS4tLms0LjIyazYuRS4uLjNFLS5VTS4zLlUzLi4uLi4uLm9Yb1guLi4uVXouLkVCZjBFLS4uc1JMMi4uT2hTLjMuLmM4ZUYuLlVKRC5JLi5Vc0s1LS5VWlMyRS0uLll2UjIuLkhYRy4zLi5vOHNGLi5RUUktSS4uazdZNS0uRTBFNUUtLlVjTlMyLi5WcDItMy4udWp0Ri4uNGRRMEkuLjZaYjUtLi5VcC1FLS5VS1pTMg,,","s":"1","sk":sk,"ui":ui},"ev":1}   
    send_加密发送_拼接提示(data_匹配, "匹配")
    send_加密发送_拼接提示(data_领取连胜奖励, "领取连胜奖励")

def make_自动联赛主程序():
    
    global i_0
    print("请输入执行次数, 执行1次大约5秒钟, 按回车确认")
    print("执行1次=5奖杯")
    i_0 = input("请输入次数:")
    print("输入完毕, 大约需要{}分钟完成".format(int(i_0)))
    for i in range(1, int(i_0) + 1):
        global count_联赛
        count_联赛 += 1
        make_自动联赛()

    input("自动联赛已完成, 请按回车继续")



#===========================查询======================
BLUE = Fore.BLUE
RED = Fore.RED 
GREEN = Fore.GREEN
WHITE = Fore.WHITE
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA


RESET = Style.RESET_ALL


LIGHTBLUE = Fore.LIGHTBLUE_EX
LIGHTRED = Fore.LIGHTRED_EX
LIGHTGREEN = Fore.LIGHTGREEN_EX
LIGHTYELLOW = Fore.LIGHTYELLOW_EX
LIGHTCYAN = Fore.LIGHTCYAN_EX
LIGHTMAGENTA = Fore.LIGHTMAGENTA_EX
LIGHTWHITE = Fore.LIGHTWHITE_EX


ORANGE = LIGHTYELLOW 
PURPLE = MAGENTA 
BLUE_CULT = LIGHTBLUE
CORAL = LIGHTRED 
TOMATO = RED 
DEEPRED = RED 
KHAKI = YELLOW 
GOLD = YELLOW   
WHEAT = WHITE 
DARKGREEN = GREEN 
TEAL = CYAN 
NAVYBLUE = BLUE 
SKYBLUE = LIGHTBLUE 
VIOLET = MAGENTA 
PLUM = LIGHTMAGENTA 
ORCHID = MAGENTA 
PINK = LIGHTMAGENTA 
HOTPINK = MAGENTA 
DEEPPINK = MAGENTA 
LIGHTPINK = LIGHTMAGENTA 
BROWN = RED 
CORNSILK = WHITE 
MISTYROSE = WHITE 


def make_查询货币():
    global pi, sk, ui 
    d = {"req": "V316", "e": {"b": "0", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    suc, r = send_加密发送_解密响应(d)
    
    if suc and r and 'p' in r and 'fg' in r['p'] and 'pif' in r and 'n' in r['pif']:
        钻石 = r['p']['fg'] 
        用户名 = r['pif']['n']
        il_list = r.get('il', [])  

        橙色培养液 = next((item['q'] for item in il_list if item['i'] == "23011"), '0')
        紫色培养液 = next((item['q'] for item in il_list if item['i'] == "23010"), '0')
        蓝色培养液 = next((item['q'] for item in il_list if item['i'] == "23009"), '0')
        绿色培养液 = next((item['q'] for item in il_list if item['i'] == "23008"), '0')
        白色培养液 = next((item['q'] for item in il_list if item['i'] == "23007"), '0')
        超z联赛币 = next((item['q'] for item in il_list if item['i'] == "23028"), '0')
        进阶书 = next((item['q'] for item in il_list if item['i'] == "23046"), '0')
        时空水晶 = next((item['q'] for item in il_list if item['i'] == "23094"), '0')
        时空粉尘 = next((item['q'] for item in il_list if item['i'] == "23095"), '0')
        神秘水晶 = next((item['q'] for item in il_list if item['i'] == "23097"), '0')
        追击币 = next((item['q'] for item in il_list if item['i'] == "23093"), '0')
        秘宝券 = next((item['q'] for item in il_list if item['i'] == "23098"), '0')
        时空能量罐 = next((item['q'] for item in il_list if item['i'] == "23112"), '0')
        时空立方 = next((item['q'] for item in il_list if item['i'] == "23113"), '0')
        万能碎片 = next((item['q'] for item in il_list if item['i'] == "23225"), '0')
        定向碎片 = next((item['q'] for item in il_list if item['i'] == "23226"), '0')
        普通祝福券 = next((item['q'] for item in il_list if item['i'] == "23123"), '0')
        高级祝福券 = next((item['q'] for item in il_list if item['i'] == "23124"), '0')
        基因原质 = next((item['q'] for item in il_list if item['i'] == "23140"), '0')
        蓝水晶 = next((item['q'] for item in il_list if item['i'] == "23228"), '0')
        紫晶币 = next((item['q'] for item in il_list if item['i'] == "23243"), '0')
        装扮券 = next((item['q'] for item in il_list if item['i'] == "23289"), '0')
        雕像 = next((item['q'] for item in il_list if item['i'] == "23394"), '0')
        蜗牛币 = next((item['q'] for item in il_list if item['i'] == "23400"), '0')
        彩色蜗牛币 = next((item['q'] for item in il_list if item['i'] == "23401"), '0')
        data = {"req": "V222", "e": {"p": {"st":1, "rs":0}, "pi": pi, "rv": "5", "sk": sk, "t": "13", "ui": ui}, "ev": 1}
        suc2, r2 = send_加密发送_解密响应(data)
        if suc2 and r2:
            try:
                if 'j' in r2 and isinstance(r2['j'], str):
                    j_data = json.loads(r2['j'])
                    无尽币 = j_data['ems']['rn']
                else:
                    print("响应数据中缺少 'j' 键或 'j' 不是字符串")
                    无尽币 = '未知'
            except (KeyError, json.JSONDecodeError) as e:
                无尽币 = '未知'
                print(f"查找无尽币失败: {e}")
        else:
            无尽币 = '未知'
        info_lines = []
        info_lines.append(f"用户名：{用户名}")
        info_lines.append(f"钻石数量：{钻石}💎")
        info_lines.append(f"橙色培养液：{橙色培养液}")
        info_lines.append(f"紫色培养液：{紫色培养液}")
        info_lines.append(f"蓝色培养液：{蓝色培养液}")
        info_lines.append(f"绿色培养液：{绿色培养液}")
        info_lines.append(f"白色培养液：{白色培养液}")
        info_lines.append(f"超z联赛币：{超z联赛币}")
        info_lines.append(f"进阶书：{进阶书}")
        info_lines.append(f"时空水晶：{时空水晶}")
        info_lines.append(f"时空粉尘：{时空粉尘}")
        info_lines.append(f"神秘水晶：{神秘水晶}")
        info_lines.append(f"追击币：{追击币}")
        info_lines.append(f"秘宝券：{秘宝券}")
        info_lines.append(f"时空能量罐：{时空能量罐}")
        info_lines.append(f"时空立方：{时空立方}")
        info_lines.append(f"万能碎片：{万能碎片}")
        info_lines.append(f"定向碎片：{定向碎片}")
        info_lines.append(f"普通祝福券：{普通祝福券}")
        info_lines.append(f"高级祝福券：{高级祝福券}")
        info_lines.append(f"基因原质：{基因原质}")
        info_lines.append(f"蓝水晶：{蓝水晶}")
        info_lines.append(f"紫晶币：{紫晶币}")
        info_lines.append(f"装扮券：{装扮券}")
        info_lines.append(f"雕像：{雕像}")
        info_lines.append(f"蜗牛币：{蜗牛币}")
        info_lines.append(f"彩色蜗牛币：{彩色蜗牛币}")
        info_lines.append(f"无尽币：{无尽币}")
        info_lines = [f"{GREEN}{line}{RESET}" for line in info_lines]
        print(f"{GREEN}=== 用户货币及相关信息 ==={RESET}")
        print_grouped(info_lines, 2, col_width=40)
        input("按回车继续")
        return 0
    else:
        print("查询失败")

#===========================全自动无尽======================
def make_获取无尽关卡():
    data = {"req": "V222", "e": {"p": {"of": 0}, "pi": pi, "rv": "5", "sk": sk, "t": "12", "ui": ui}, "ev": 1}
    suc, json_object = send_加密发送_解密响应(data)
    if suc:
        return int(json.loads(json_object["j"])["l"])
    else:
        print("获取无尽关卡错误")


def make_钻石重置无尽():
    global uk
    make_ukugd()
    data = {"req": "V209", "e": {"oi": "10300", "pi": pi, "q": "1", "si": "1", "sk": sk, "ui": ui, "uk": str(int(uk) + 1)},
            "ev": 1}
    suc, _ = send_加密发送_拼接提示(data, "使用钻石重置")
    return suc


def make_自动重置无尽():
    data_ad = {"req": "V921", "e": {"oi": "10308", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    data_free = {"req": "V319", "e": {"g": "12550", "l": "0", "pi": pi, "sk": sk, "t": "0", "ui": ui}, "ev": 1}
    suc, _ = send_加密发送_拼接提示(data_free, "免费重置无尽")
    if not suc:
        suc2, _ = send_加密发送_拼接提示(data_ad, "广告重置无尽")
        if not suc2:
                return make_钻石重置无尽()
    return True

def make_循环无尽另():
    data_进入无尽 = {"req": "V303", "e": {"al": [{"id": 10622, "abi": 0, "type": 1, "config_version": 1}], "ci": "93", "cs": "0", "pack": 渠道, "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    send_加密发送_拼接提示(data_进入无尽, "进入无尽")
    total_packages = 149
    current_level = int(make_获取无尽关卡())
    print(f"初始关卡：{current_level}")
    if current_level >= total_packages:
        print("检测到已经达到149关，立即重置无尽...")
        make_自动重置无尽()
        current_level = int(make_获取无尽关卡())
        print(f"重置后关卡：{current_level}")
        
    mode_choice = input("请选择模式：1 - 循环无尽  2 - 有分无尽：").strip()
    if mode_choice == "1":
        rounds = int(input("请输入循环轮数: "))
    else:
        rounds = 1
    print(f"模式选择：{mode_choice}，轮数：{rounds}")
    folder = "无尽"
    if not os.path.exists(folder):
        os.mkdir(folder)
        print("创建文件夹：", folder)
    else:
        for f_name in os.listdir(folder):
            file_path = os.path.join(folder, f_name)
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"删除 {file_path} 失败：{e}")
    for i in range(total_packages):
        data_v322 = {"req":"V322","e":{"acd":{"g":5318,"ubn":0,"uebn":1,"upnl":[{"id":1013,"n":5},{"id":111035,"n":5}]},"fr":"1","pi":pi,"ri":{"l":i,"ml":i,"lwml":1,"lc":[1,1,1,1,1],"eb":5,"eub":0,"pl":"H4sIAAAAAAAAE32VQW-CQBCF_5AHFGzT45YlcY2zZCNW6a0lrQFr2sQ0C_vriywY1Hm9kdnwzfDe22Ebnsq3rSnTKrFabk7qGLXP-mm1GOrKkhTTNLble6keKAxOH83y5zVun7OkJpkHq3j5q6rvmhbjMxFS07-TPY947TuZaC686zNLTvQzJPZzXT-q49ehY0tl2T6VaOfLh7Po-h2a83VT8_Ui5OuJ6-vuqp6d5-U08984fH96q0vM1c9a7od5p6M-Tat_2-fQ93m59cbS2vP07pZnQmbujpdmAnkdsV53Ou-nkCdzyNOYx-na8xTkEZtFUVOJ-hQR6qMvut71Cdk-ngd11S7BPDxfgHmEeDPdIF4-h7wK-jTDvufQd10ZyCNuvky4Ia_3fQzWQUJdHdaBavbeyg3MAzn4PY3m_Ovu2cGi_ZCyO7XfD5CnOP_6fcPloeMFeD7D-ed5GZf_jsfnv-MVkJfKPdLP4vwnnH7eD3Y-7wfOkeL9kAWXB98H57jRuA_OUcXtr_YfWxWgDv-9DutG_-QY7o0A35cN3Md65MPOTCZ_5-jpBzgIAAA,","dm":"29014cf0a89d79180ef1f92853ce68cc","ls":750,"ds":0,"bn":1,"bu":0,"m":2110,"jc":6,"jl":5,"par":80,"pas":500,"on":"823ac77132cc44579dd6c51ce2094c63","alt":15,"amt":15,"cil":[]},"sk":sk,"ui":ui,"w":"4"},"ev":1}
        plain = json.dumps(data_v322, separators=(',', ':'))
        encrypted_text = CNNetwork.encrypt(plain)
        file_path = os.path.join(folder, f"package_{i+1:03d}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(encrypted_text)
    print(f"149个包已生成，存放于文件夹：{folder}")
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=150, pool_maxsize=150)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    overall_start_time = time.time()
    for round_index in range(rounds):
        round_start_time = time.time()
        current_level = int(make_获取无尽关卡())
        print(f"【轮次 {round_index+1}】当前关卡：{current_level}")
        level = current_level + 1
        while level <= total_packages:
            file_path = os.path.join(folder, f"package_{level:03d}.txt")
            with open(file_path, "r", encoding="utf-8") as f:
                package_text = f.read()
            response = session.post(url, headers=headers, data=package_text)
            if response.status_code == 403:
                print(f"关卡 {level}: 你被锁ip，等待301秒以解除限制...")
                time.sleep(301)
                current_level = int(make_获取无尽关卡())
                print(f"更新后的关卡：{current_level}")
                level = current_level + 1
                continue
            if response.status_code != 200:
                print(f"关卡 {level} HTTP响应非200: {response.status_code}")
            try:
                resp_json = json.loads(response.text)
                if resp_json.get("r") == 0:
                    print(f"关卡 {level} 过关成功")
                    success_flag = True
                else:
                    decrypted_response = CNNetwork.decrypt(response.text)
                    print(f"关卡 {level} 过关失败，返回：{decrypted_response}")
                    success_flag = False
            except Exception as e:
                print(f"关卡 {level} 响应解析错误：{e}")
                success_flag = False

            if level < 65:
                time.sleep(0.1)
            else:
                if not success_flag:
                    if mode_choice == "1":
                        print(f"关卡 {level} 失败，等待15秒...")
                        time.sleep(15)
                    else:
                        print(f"关卡 {level} 失败，等待17秒...")
                        time.sleep(17)
                    current_level = int(make_获取无尽关卡())
                    print(f"更新后的关卡：{current_level}")
                    level = current_level + 1
                    continue
                else:
                    if mode_choice == "2":
                        time.sleep(17)
            level += 1
        round_end_time = time.time()
        round_duration = round_end_time - round_start_time
        print(f"【轮次 {round_index+1}】本轮通关耗时：{round_duration:.2f} 秒")
        if mode_choice == "1" and round_index < rounds - 1:
            if int(make_获取无尽关卡()) >= total_packages:
                print("达到149关，开始重置无尽……")
                make_自动重置无尽()
    overall_end_time = time.time()
    overall_duration = overall_end_time - overall_start_time
    print(f"全部循环通关总耗时：{overall_duration:.2f} 秒")
    average_time = overall_duration / rounds
    print(f"每轮平均耗时：{average_time:.2f} 秒")

def send_无尽(data: str, intent: str,次数):
    response = send(data)
    success = "\"r\":0" in response
    print(f"自动无尽第{次数}次 ",intent, "成功🎉" if success else "失败")
    if not success:
        response = send(data)
        success = "\"r\":0" in response
        print(f"自动无尽第{次数}次 ",intent, "成功🎉" if success else "失败")
    return success, response

def 新无尽(a):
    global pi, sk, ui
    关卡数=make_获取无尽关卡()
    print(f"当前关卡:{关卡数}")
    if 关卡数>=149:
        return True
    
    if 关卡数<65:
        for i in range(关卡数,65):
            data = {"req":"V322","e":{"acd":{"g":5318,"ubn":0,"uebn":1,"upnl":[{"id":1013,"n":5},{"id":111035,"n":5}]},"fr":"1","pi":pi,"ri":{"l":i,"ml":i,"lwml":1,"lc":[1,1,1,1,1],"eb":5,"eub":0,"pl":"H4sIAAAAAAAAE32VQW-CQBCF_5AHFGzT45YlcY2zZCNW6a0lrQFr2sQ0C_vriywY1Hm9kdnwzfDe22Ebnsq3rSnTKrFabk7qGLXP-mm1GOrKkhTTNLble6keKAxOH83y5zVun7OkJpkHq3j5q6rvmhbjMxFS07-TPY947TuZaC686zNLTvQzJPZzXT-q49ehY0tl2T6VaOfLh7Po-h2a83VT8_Ui5OuJ6-vuqp6d5-U08984fH96q0vM1c9a7od5p6M-Tat_2-fQ93m59cbS2vP07pZnQmbujpdmAnkdsV53Ou-nkCdzyNOYx-na8xTkEZtFUVOJ-hQR6qMvut71Cdk-ngd11S7BPDxfgHmEeDPdIF4-h7wK-jTDvufQd10ZyCNuvky4Ia_3fQzWQUJdHdaBavbeyg3MAzn4PY3m_Ovu2cGi_ZCyO7XfD5CnOP_6fcPloeMFeD7D-ed5GZf_jsfnv-MVkJfKPdLP4vwnnH7eD3Y-7wfOkeL9kAWXB98H57jRuA_OUcXtr_YfWxWgDv-9DutG_-QY7o0A35cN3Md65MPOTCZ_5-jpBzgIAAA,","dm":"29014cf0a89d79180ef1f92853ce68cc","ls":750,"ds":0,"bn":1,"bu":0,"m":2110,"jc":6,"jl":5,"par":80,"pas":500,"on":"823ac77132cc44579dd6c51ce2094c63","alt":15,"amt":15,"cil":[]},"sk":sk,"ui":ui,"w":"4"},"ev":1}
            send_加密发送_拼接提示(data, f"自动无尽第{a}次,无尽通关第{i}关")
    else:
        待发送=[]
        for 关卡 in range(关卡数,关卡数+20):
            data = {"req":"V322","e":{"acd":{"g":5318,"ubn":0,"uebn":1,"upnl":[{"id":1013,"n":5},{"id":111035,"n":5}]},"fr":"1","pi":pi,"ri":{"l":关卡,"ml":关卡,"lwml":1,"lc":[1,1,1,1,1],"eb":5,"eub":0,"pl":"H4sIAAAAAAAAE32VQW-CQBCF_5AHFGzT45YlcY2zZCNW6a0lrQFr2sQ0C_vriywY1Hm9kdnwzfDe22Ebnsq3rSnTKrFabk7qGLXP-mm1GOrKkhTTNLble6keKAxOH83y5zVun7OkJpkHq3j5q6rvmhbjMxFS07-TPY947TuZaC686zNLTvQzJPZzXT-q49ehY0tl2T6VaOfLh7Po-h2a83VT8_Ui5OuJ6-vuqp6d5-U08984fH96q0vM1c9a7od5p6M-Tat_2-fQ93m59cbS2vP07pZnQmbujpdmAnkdsV53Ou-nkCdzyNOYx-na8xTkEZtFUVOJ-hQR6qMvut71Cdk-ngd11S7BPDxfgHmEeDPdIF4-h7wK-jTDvufQd10ZyCNuvky4Ia_3fQzWQUJdHdaBavbeyg3MAzn4PY3m_Ovu2cGi_ZCyO7XfD5CnOP_6fcPloeMFeD7D-ed5GZf_jsfnv-MVkJfKPdLP4vwnnH7eD3Y-7wfOkeL9kAWXB98H57jRuA_OUcXtr_YfWxWgDv-9DutG_-QY7o0A35cN3Md65MPOTCZ_5-jpBzgIAAA,","dm":"29014cf0a89d79180ef1f92853ce68cc","ls":750,"ds":0,"bn":1,"bu":0,"m":2110,"jc":6,"jl":5,"par":80,"pas":500,"on":"823ac77132cc44579dd6c51ce2094c63","alt":15,"amt":15,"cil":[]},"sk":sk,"ui":ui,"w":"4"},"ev":1}          
            data=CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
            待发送.append(data)
                    
        for i in 待发送:
            time.sleep(无尽延迟)
            threading.Thread(target=send_无尽,args=(i,f'第{关卡数}关',a)).start()
            关卡数+=1
def 无尽主程序(a):           
    while True:
      if 新无尽(a):
        print("无尽模式已完成")
        return True
      time.sleep(15)
def 全自动无尽():
    count = 0
    total_time = 0
    min_time = float('inf')

    set_times = int(input("优先使用免费次数重置, 用完后将会消耗钻石重置\n请输入想要通关多少次, 按回车继续:"))
    if make_获取无尽关卡() == 149:
        make_自动重置无尽()

    while True:
        start_time = time.time()
        if 无尽主程序(count + 1):
            end_time = time.time()
            elapsed_time = end_time - start_time
            total_time += elapsed_time
            min_time = min(min_time, elapsed_time)
            print(f"第{count + 1}次通关用时: {elapsed_time:.2f}秒")
            count += 1
        if count >= set_times:
            break
        make_自动重置无尽()

    print(f"自动无尽完成, 共重置了{count}次")
    print(f"最短通关时间: {min_time:.2f}秒")
    print(f"总通关时间: {total_time:.2f}秒")
    print(f"平均通关时间: {total_time / count:.2f}秒")
print(f'当前无尽延迟为{无尽延迟}')
#===========================旅行原木======================
def make_原木宝箱():
    difficulties = [{"name": "简单", "ct": "1"}, {"name": "困难", "ct": "2"}, {"name": "终极", "ct": "3"}]
    fragment_count = {}
    # 循环发送每种难度的请求
    for difficulty in difficulties:
        print(f"{ORANGE}开始 {BLUE_CULT}{difficulty['name']} {ORANGE}世界任务{RESET}")
        
        # 每种难度循环20次（bt从1到20）
        for bt in range(1, 16):
            d = {"req": "V791", "e": {"bt": str(bt), "ct": difficulty['ct'], "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
            suc, r_世界任务 = send_加密发送_解密响应(d)
            
            if suc and isinstance(r_世界任务, dict) and 'l' in r_世界任务:
                rewards = r_世界任务['l']
                for reward in rewards:
                    item_id = str(reward['i'])
                    quantity = reward['q']
                    item_name = 植物碎片字典.get(item_id, f"未知碎片({item_id})")
                    
                    if item_name in fragment_count:
                        fragment_count[item_name] = fragment_count.get(item_name, 0) + quantity
                    else:
                        fragment_count[item_name] = quantity
                    
                    print(f"  {CYAN}奖励为:{RESET} {item_name}*{GOLD}{quantity}{RESET}")
            else:
                print(f"  {CYAN}{difficulty['name']}{RESET}任务 第 {GOLD}{bt}{RESET} 次通关 {DEEPRED}失败{RESET}")
            time.sleep(0.5)

    print(f"\n{ORANGE}获得的植物碎片统计:{RESET}")
    for item_name, total_quantity in sorted(fragment_count.items()):
        item_id = next((k for k, v in 植物碎片字典.items() if v == item_name), None)
        if item_id:
            item_quality = 碎片品质字典.get(item_id, "白")
        else:
            item_quality = "白"
        quality_color = 碎片颜色字典.get(item_quality, "\033[97m")
        print(f"  [{quality_color}{item_quality}{RESET}]{WHITE}{item_name}{RESET}{GOLD}{total_quantity}{RESET}片") 
#===========================踏青响叮当======================
def make_火焰训练():
    print("请选择要打的关卡(1-3关):")
    level_choice = input("输入关卡号(1，2，3): ")
    while level_choice not in ['1', '2', '3']:
        print("无效的选择，请输入1、2或3")
        level_choice = input("输入关卡号(1，2，3): ")
    level_index = str(int(level_choice))
    total_input = input("请输入要刷的总分: ").strip()
    try:
        total_score = float(total_input)
    except Exception as e:
        print("输入分数有误")
        return
    alpha = 2.0  
    parts_raw = [random.gammavariate(alpha, 1) for _ in range(10)]
    s_raw = sum(parts_raw)
    parts = [x / s_raw * total_score for x in parts_raw]
    parts_str = [f"{part:.6f}" for part in parts]
    total_score_str = f"{total_score:.6f}"

    d={"req":"V303","e":{"al":[{"id":10896,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(10):
        data_package = {"req": "V1094","e": {"p": str(i),"pi": pi,"r": "91611","s": parts_str[i],"sk": sk,"ui": ui},"ev": 1}
        send_加密发送_拼接提示(data_package, f"第{i+1}个包 {parts_str[i]} 分发送")
    data_前三关 = {"req": "V1091","e": {"l": level_index, "pi": pi, "s": total_score_str, "sk": sk, "ui": ui ,"w":"gingleBell_s1"},"ev": 1}
    send_加密发送_拼接提示(data_前三关, f"火焰训练第{level_choice}关领取{total_score_str}分")
def make_电击训练():
    print("请选择要打的关卡(1-3关):")
    level_choice = input("输入关卡号(1，2，3): ")
    while level_choice not in ['1', '2', '3']:
        print("无效的选择，请输入1、2或3")
        level_choice = input("输入关卡号(1，2，3): ")
    level_index = str(int(level_choice))
    total_input = input("请输入要刷的总分: ").strip()
    try:
        total_score = float(total_input)
    except Exception as e:
        print("输入分数有误")
        return
    alpha = 2.0  
    parts_raw = [random.gammavariate(alpha, 1) for _ in range(10)]
    s_raw = sum(parts_raw)
    parts = [x / s_raw * total_score for x in parts_raw]
    parts_str = [f"{part:.6f}" for part in parts]
    total_score_str = f"{total_score:.6f}"
    d={"req":"V303","e":{"al":[{"id":10896,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(10):
        data_package = {"req": "V1094","e": {"p": str(i),"pi": pi,"r": "91611","s": parts_str[i],"sk": sk,"ui": ui},"ev": 1}
        send_加密发送_拼接提示(data_package, f"第{i+1}个包 {parts_str[i]} 分发送")
    for i in range(1):
        data_前三关 = {"req": "V1091","e": {"l": level_index, "pi": pi, "s": total_score_str, "sk": sk, "ui": ui ,"w":"gingleBell_s2"},"ev": 1}
    send_加密发送_拼接提示(data_前三关, f"电击训练第{level_choice}关领取{total_score_str}分")
def make_物理训练():
    print("请选择要打的关卡(1-3关):")
    level_choice = input("输入关卡号(1，2，3): ")
    while level_choice not in ['1', '2', '3']:
        print("无效的选择，请输入1、2或3")
        level_choice = input("输入关卡号(1，2，3): ")
    level_index = str(int(level_choice))
    total_input = input("请输入要刷的总分: ").strip()
    try:
        total_score = float(total_input)
    except Exception as e:
        print("输入分数有误")
        return
    alpha = 2.0  
    parts_raw = [random.gammavariate(alpha, 1) for _ in range(10)]
    s_raw = sum(parts_raw)
    parts = [x / s_raw * total_score for x in parts_raw]
    parts_str = [f"{part:.6f}" for part in parts]
    total_score_str = f"{total_score:.6f}"
    d={"req":"V303","e":{"al":[{"id":10896,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(10):
        data_package = {"req": "V1094","e": {"p": str(i),"pi": pi,"r": "91611","s": parts_str[i],"sk": sk,"ui": ui},"ev": 1}
        send_加密发送_拼接提示(data_package, f"第{i+1}个包 {parts_str[i]} 分发送")
    for i in range(1):
        data_前三关 = {"req": "V1091","e": {"l": level_index, "pi": pi, "s": total_score_str, "sk": sk, "ui": ui ,"w":"gingleBell_s3"},"ev": 1}
    send_加密发送_拼接提示(data_前三关, f"物理训练第{level_choice}关领取{total_score_str}分")
def make_响叮当奖励():
    x = 0  
    for i in range(1, 11):
        data = {"req": "V1093", "e": {"id": str(1000 + i), "pi": pi, "sk": sk, "ui": ui},
                "ev": 1}
        suc, _ = send_加密发送_拼接提示(data, "领取奖励")
        if suc:
            x += 1
            if x == 12:
                print("奖励领取完毕")
                break
#===========================植树节趣味竞赛======================
def make_趣味竞赛空中战争():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(1):
        空中战争={"req":"V1070","e":{"id":4,"pi":pi,"score":"4000","sk":sk,"type":1,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(空中战争, "通关空中战争普通关卡".format(i))
    for i in range(1):
        空中战争={"req":"V1070","e":{"id":4,"pi":pi,"score":"4000","sk":sk,"type":2,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(空中战争, "通关空中战争困难关卡".format(i))
def make_趣味竞赛记忆骆驼牌():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(1):
        骆驼牌={"req":"V1070","e":{"id":2,"pi":pi,"score":"4000","sk":sk,"type":1,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(骆驼牌, "通关记忆骆驼牌普通关卡".format(i))
    for i in range(1):
        骆驼牌={"req":"V1070","e":{"id":2,"pi":pi,"score":"4000","sk":sk,"type":2,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(骆驼牌, "通关记忆骆驼牌困难关卡".format(i))
def make_趣味竞赛坚果保龄球():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(1):
        坚果保龄球={"req":"V1070","e":{"id":3,"pi":pi,"score":"4000","sk":sk,"type":1,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(坚果保龄球, "通关坚果保龄球普通关卡".format(i))
    for i in range(1):
        坚果保龄球={"req":"V1070","e":{"id":3,"pi":pi,"score":"4000","sk":sk,"type":2,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(坚果保龄球, "通关坚果保龄球困难关卡".format(i))
def make_趣味竞赛猜猜我是谁():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(1):
        猜猜我是谁={"req":"V1070","e":{"id":1,"pi":pi,"score":"4000","sk":sk,"type":1,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(猜猜我是谁, "通关猜猜我是谁普通关卡".format(i))
    for i in range(1):
        猜猜我是谁={"req":"V1070","e":{"id":1,"pi":pi,"score":"4000","sk":sk,"type":2,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(猜猜我是谁, "通关猜猜我是谁困难关卡".format(i))
def make_趣味竞赛汽车华容道():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(d,'进入活动')
    for i in range(1):
        汽车华容道={"req":"V1070","e":{"id":5,"pi":pi,"score":"4000","sk":sk,"type":1,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(汽车华容道, "通关汽车华容道普通关卡".format(i))
    for i in range(1):
        汽车华容道={"req":"V1070","e":{"id":5,"pi":pi,"score":"4000","sk":sk,"type":2,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(汽车华容道, "通关汽车华容道困难关卡".format(i))

def make_趣味竞赛奖励():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    for i in range(1,9):
        data2={"req":"V1071","e":{"id":str(0 + i),"pi":pi,"sk":sk,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(data2, "领取第{}个奖励".format(i))

def make_植树节趣味竞赛无限刷币():
    d={"req":"V303","e":{"al":[{"id":10893,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    for i in range(9999999):
        空中战争刷币={"req":"V1070","e":{"id":0,"pi":pi,"score":"4000","sk":sk,"type":2,"ui":ui},"ev":1}
        suc,r=send_加密发送_拼接提示(空中战争刷币, "刷币第{}次".format(i))
#===========================欢乐植树======================
def make_欢乐植树():
    for i in range(1,8):
        data_宝箱1 = {"req": "V985",
                     "e": {"pi": pi,"sk": sk, "t": "1","ti": str(1001 + i), "ui": ui},"ev": 1}
        send_加密发送_拼接提示(data_宝箱1, "第{}个任务领取".format(i))
#===========================买电池======================
def make_买电池():
    make_ukugd()
    make_进入追击()
    买前电池 = {"req": "V303",
                          "e": {"al": [{"id": 10800, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                                "pack": "", "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    r = send_加密发送_解密响应(买前电池)
    try:
        r_0 = json.loads(r[1][0]["data"])
        r_电池 = int(r_0['f'])
        print(f"\n买之前电池数量: {r_电池}🔋")  
    except (KeyError, IndexError, ValueError) as e:
        print(f"获取电池数量失败: {e}")
    d = {"req":"V316","e":{"b":"0","pi":pi,"sk":sk,"ui":ui,},"ev":1}
    suc, r = send_加密发送_解密响应(d)
    
    if suc and r and 'p' in r and 'fg' in r['p'] and 'pif' in r and 'n' in r['pif']:
        钻石 = r['p']['fg']   
        print(f"{BLUE}当前钻石数量：{钻石}{RESET}💎")
    global uk
    battery_counts = int(input("\n请输入想要买的电池数量, 按回车继续:"))
    data_query_pursuit = {'req': 'V209', 'e': {'oi': '52304', 'pi': pi, 'q': battery_counts, 'si': '1', 'sk': sk, 'ui': ui, "uk": str(int(uk) + 1)}, 'ev': 1}
    send_加密发送_拼接提示(data_query_pursuit, "获取电池")
    买完后电池 = {"req": "V303",
                          "e": {"al": [{"id": 10800, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                                "pack": "", "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    r = send_加密发送_解密响应(买完后电池)
    try:
        r_0 = json.loads(r[1][0]["data"])
        r_电池 = int(r_0['f'])
        print(f"买之后电池数量: {r_电池}🔋")  
    except (KeyError, IndexError, ValueError) as e:
        print(f"获取电池数量失败: {e}")
    d = {"req":"V316","e":{"b":"0","pi":pi,"sk":sk,"ui":ui,},"ev":1}
    suc, r = send_加密发送_解密响应(d)
    
    if suc and r and 'p' in r and 'fg' in r['p'] and 'pif' in r and 'n' in r['pif']:
        钻石 = r['p']['fg']   
        print(f"{BLUE}剩余钻石数量：{钻石}{RESET}💎")

#===========================追击排行榜======================
def make_追击排行榜():
    req_param = {"req": "V933", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    suc, r = send_加密发送_解密响应(req_param)
    if not suc:
        print("获取追击排行榜失败")
        return
    try:
        lb = r['lb']
        print("\n\t【追击排行榜】")
        for i, 排名信息 in enumerate(lb):
            print(f"第{i + 1}名\t{排名信息['n']}\t{排名信息['s']}分")
    except RuntimeError:
        print("查询追击排行榜失败")

def make_查询追击每关分数():
    data_query_pursuit = {"req": "V303",
                          "e": {"al": [{"id": 10800, "abi": 0, "type": 1, "config_version": 1}], "ci": "91", "cs": "0",
                                "pack": "", "pi": pi, "sk": sk, "ui": ui,"v": newest_version}, "ev": 1}
    r = send_加密发送_解密响应(data_query_pursuit)
    try:
        r_0 = json.loads(r[1][0]["data"])
        r_data = {
            "普通关分数情况": r_0['lms'],
            "boss关分数情况": r_0['bms'],
            "总分数": r_0['s'],
            "排名": r_0['r'],
            "电池":r_0['f']
        }

        print(f"{ORANGE}\n\t【个人信息情况】\033[0m")
        print(f"{PURPLE}总分数：\t{r_data['总分数']}\033[0m")
        print(f"{PURPLE}排名：\t{r_data['排名']}\033[0m")
        print(f"{PURPLE}电池：\t{r_data['电池']}\033[0m")

        print(f"{ORANGE}\t【普通关分数情况】\033[0m")
        for i, 小关情况 in enumerate(r_data["普通关分数情况"]):
            for j, s in enumerate(小关情况):
                if i == 4 and j == 2:
                    break
                print(f"{WHITE}普通关{i+1}-{j+1}：\t{s}分\033[0m")

        print(f"{ORANGE}\t【boss关分数情况】\033[0m")
        for i, s in enumerate(r_data["boss关分数情况"]):
            print(f"{GREEN}boss关{i+1}：\t{s}分\033[0m")


    except RuntimeError:
        print("查询追击信息失败")
#===========================买名片======================
def make_名片():
    for i in range(1, 2):
        d={"req":"V303","e":{"al":[{"id":10840,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":"3.6.3"},"ev":1}
        send_加密发送_拼接提示(d,'进入活动')
        b={"req": "V723",
                     "e": {"c": "100", "f": "0", "k": "0", "pi": pi, "pk": "0,1,2,3,4,5,6,7", "s": "0", "sk": sk,
                           "t": "2", "ui": ui, "w": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"}, "ev": 1}
        send_加密发送_拼接提示(b,'进入商店')
        data_名片1 = {"req":"V392","e":{"ci":"50","gi":"61025","mi":"23403","pi":pi,"q":"1","si":"11","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data_名片1, "名片购买".format(i))
        data_名片2 = {"req":"V392","e":{"ci":"50","gi":"61022","mi":"23403","pi":pi,"q":"1","si":"11","sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data_名片2, "名片购买".format(i))
#===========================充值返利======================
def make_充值返利():
    for i in range(1):
        data_返利 = {"req": "V402",
                "e": {"am": 30,"pi": pi, "sk": sk,"ui": ui,"v": newest_version}, "ev": 1}
        send_加密发送_拼接提示(data_返利, "充值返利领取")
#===========================问卷调查======================
def make_问卷调查():
    for i in range(1):
        d={"req":"V303","e":{"al":[{"id":10833,"abi":0,"type":1,"config_version":1}],"ci":"103","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
        send_加密发送_拼接提示(d,'进入活动')
        data_调查 = {"req": "V956",
                "e": {"pi": pi, "sk": sk,"ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data_调查, "188钻石/300装扮券领取🎇")
#===========================查询碎片======================
def make_查询碎片():
    global pi, sk, ui 
    请求数据 = {"req": "V316", "e": {"b": "0", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    suc, r = send_加密发送_解密响应(请求数据)
    if suc and r:
        if 'pcl' in r:
            碎片列表 = r['pcl']
            品质顺序 = ["白", "绿", "蓝", "紫", "橙"]
            品质分类 = {品质: [] for 品质 in 品质顺序}
            for 单个碎片 in 碎片列表[:280]:
                碎片代码 = 单个碎片['i']
                碎片数量 = 单个碎片['q']
                植物名称 = 植物碎片字典.get(碎片代码, f"未知碎片({碎片代码})")
                碎片品质 = 碎片品质字典.get(碎片代码, "白")
                碎片颜色 = 碎片颜色字典.get(碎片品质, "\033[97m")
                数量颜色 = "\033[93m"  
                白色 = "\033[97m"      
                显示字符串 = f"{白色}[{碎片颜色}{碎片品质}{白色}]{白色}{植物名称}{数量颜色}x{碎片数量}\033[0m"
                品质分类[碎片品质].append(显示字符串) 
            for 品质 in 品质顺序:
                items = 品质分类[品质]
                if items:
                    print(f"——品质 {品质}——")
                    print_grouped(items, 2, col_width=30)
            return 品质分类
        else:
            print("未找到碎片信息")
    else:
        print("查询失败")
    return None
#===========================查询植物======================
def make_查询植物():
    植物请求 = {"req": "V316", "e": {"b": "0", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    suc, r = send_加密发送_解密响应(植物请求)
    if suc and r:
        if "pl" in r:
            植物列表 = r["pl"]
            if not 植物列表:
                print("没有找到任何植物信息。")
                return
            print("\n\033[92m查询到的植物信息如下：\033[0m")
            已解锁植物数 = len(植物列表)
            阶级统计 = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
            品质顺序 = ["白", "绿", "蓝", "紫", "橙"]
            plant_classification = {品质: [] for 品质 in 品质顺序}
            
            for 植物 in 植物列表:
                植物代码 = 植物.get("i", "未知代码")
                try:
                    等级 = int(植物.get("s", -1))
                except ValueError:
                    等级 = -1 
                if 0 <= 等级 < 5:
                    阶级统计[等级 + 1] += 1
                等级颜色 = LIGHTGREEN  
                等级描述 = f"{等级颜色}{等级 + 1}阶{RESET}"
                植物名称 = 植物字典.get(植物代码, "未知植物") 
                植物品质 = 植物品质字典.get(植物代码, "白")
                品质颜色 = 碎片颜色字典.get(植物品质, "\033[97m")  
                plant_info = f"[{品质颜色}{植物品质}\033[0m]{植物名称}————等级:{等级描述}"
                if 植物品质 not in plant_classification:
                    plant_classification[植物品质] = []
                plant_classification[植物品质].append(plant_info)
            for 品质 in 品质顺序:
                items = plant_classification.get(品质, [])
                if items:
                    print(f"=== 品质 {品质} ===")
                    print_grouped(items, 2, col_width=30)
                    
            print(f"已解锁植物总数：{YELLOW}{已解锁植物数}个{RESET}")
            for 阶级, 数量 in 阶级统计.items():
                显示颜色 = LIGHTGREEN
                print(f"{阶级}阶植物：{显示颜色}{数量}个{RESET}")
        else:
            print("未找到 pl 字段")
    else:
        print("查询植物信息失败")
#===========================查询神器======================
def make_查询神器():
    神器 = {"req": "V316", "e": {"b": "0", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    suc, r = send_加密发送_解密响应(神器)
    
    if suc and r:
        if "al" in r:
            神器列表 = r["al"]
            神器数量 = len(神器列表)
            print("已拥有的神器:")
            print("-" * 200) 
            artifact_lines = []
            for 神器 in 神器列表:
                神器id = 神器["i"]
                等级 = int(神器["l"]) 
                阶数 = int(神器["s"]) 
                
                神器名称 = 神器字典.get(str(神器id), f"未知神器({神器id})")
                
                if 1 <= 等级 <= 10:
                    等级颜色 = LIGHTGREEN
                elif 11 <= 等级 <= 20:
                    等级颜色 = LIGHTRED
                elif 21 <= 等级 <= 30:
                    等级颜色 = LIGHTMAGENTA  
                elif 31 <= 等级 <= 40:
                    等级颜色 = LIGHTYELLOW
                else:
                    等级颜色 = WHITE

                if 阶数 == 1:
                    阶数颜色 = LIGHTGREEN
                elif 阶数 == 2:
                    阶数颜色 = LIGHTRED
                elif 阶数 == 3:
                    阶数颜色 = LIGHTMAGENTA
                elif 阶数 == 4:
                    阶数颜色 = LIGHTYELLOW
                else:
                    阶数颜色 = WHITE
                
                artifact_info = f"{神器名称} 等级:{等级颜色}{等级}级{RESET} 阶数:{阶数颜色}{阶数}阶{RESET}"
                artifact_lines.append(artifact_info)
            
            print_grouped(artifact_lines, 2, col_width=20)
            print("-" * 200)
            print(f"共拥有{LIGHTRED}{神器数量}个{RESET}神器")
        else:
            print("未获取到神器数据")
    else:
        print("获取神器数据失败")

def make_免费箱子():
    data_免费白箱 = {"req": "V313", "e": {"ad": "0", "f": "2", "lt": "1", "n": "10","pi": pi, "sk": sk, "t": "1", "ui": ui}, "ev": 1}
    data_免费紫箱 = {"req": "V313", "e": {"ad": "0", "f": "2", "lt": "1", "n": "10","pi": pi, "sk": sk, "t": "2", "ui": ui}, "ev": 1}
    data_免费橙箱 = {"req": "V313", "e": {"ad": "1", "f": "2", "lt": "1", "n": "1","pi": pi, "sk": sk, "t": "3", "ui": ui}, "ev": 1}
    data_免费装扮箱 = {"req": "V313", "e": {"ad": "0", "f": "2", "lt": "1", "n": "10","pi": pi, "sk": sk, "t": "4", "ui": ui}, "ev": 1}
    total_rewards = {}  
    def 处理响应(箱子, use_装扮=False):
        suc, r = send_加密发送_解密响应(箱子)
        if suc:
            if 'bl' in r:
                for item in r['bl']:
                    代码 = str(item['i'])
                    数量 = item.get('q', 0)
                    if use_装扮:
                        套装名称 = 植物装扮字典.get(代码, None)
                        装扮碎片 = 植物装扮碎片字典.get(代码, None)
                        if 套装名称:
                            reward_name = f"装扮{套装名称}"
                            print(f"抽到了装扮：{套装名称} x {数量}")
                        elif 装扮碎片:
                            reward_name = 装扮碎片
                            print(f"抽到了 {装扮碎片} x {数量}")
                        else:
                            reward_name = f"未知({代码})"
                            print(f"代码：{代码}，数量：{数量}")
                    else:
                        植物名称 = 植物字典.get(代码, None)
                        碎片名称 = 植物碎片字典.get(代码, None)
                        if 植物名称:
                            reward_name = f"植物{植物名称}"
                            print(f"抽到了植物：{植物名称} x {数量}")
                        elif 碎片名称:
                            reward_name = 碎片名称
                            print(f"抽到了 {碎片名称} x {数量}")
                        else:
                            reward_name = f"未知({代码})"
                            print(f"代码：{代码}，数量：{数量}")
                    total_rewards[reward_name] = total_rewards.get(reward_name, 0) + 数量
            if 'p' in r and 'fg' in r['p']:
                钻石 = r['p']['fg']
                print(f"当前钻石数量: {钻石}💎")
            if 'p' in r and 'uk' in r['p']:
                uk = r['p']['uk']
                print(f"当前UK: {uk}")
        else:
            print("请求失败，未获取箱子结果")
    print("正在抽取免费白箱10连...")
    处理响应(data_免费白箱)
    print("正在抽取免费紫箱10连...")
    处理响应(data_免费紫箱)
    for i in range(2):
        print(f"正在抽取免费橙箱单抽 第 {i+1} 次...")
        处理响应(data_免费橙箱)
    print("正在抽取免费装扮10连...")
    处理响应(data_免费装扮箱, use_装扮=True)
    print("本次累计获得奖励：")
    if total_rewards:
        for reward, total_qty in total_rewards.items():
            print(f"{reward} x {total_qty}")
    else:
        print("未获得任何奖励")

#===========================秘宝箱子======================
def make_潘妮宝箱():
    白箱188 = {"req": "V313","e": {"ad": "0", "f": "0", "lt": "1", "n": "10", "pi": pi, "sk": sk, "t": "1", "ui": ui},"ev": 1}
    紫箱688 = {"req": "V313","e": {"ad": "0", "f": "0", "lt": "1", "n": "10", "pi": pi, "sk": sk, "t": "2", "ui": ui},"ev": 1}
    橙箱2888 = {"req": "V313","e": {"ad": "0", "f": "0", "lt": "1", "n": "10", "pi": pi, "sk": sk, "t": "3", "ui": ui},"ev": 1}
    data_免费白箱 = {"req": "V313","e": {"ad": "0", "f": "2", "lt": "1", "n": "10", "pi": pi, "sk": sk, "t": "1", "ui": ui},"ev": 1}
    data_免费紫箱 = {"req": "V313","e": {"ad": "0", "f": "2", "lt": "1", "n": "10", "pi": pi, "sk": sk, "t": "2", "ui": ui},"ev": 1}
    data_免费橙箱 = {"req": "V313","e": {"ad": "0", "f": "2", "lt": "1", "n": "10", "pi": pi, "sk": sk, "t": "3", "ui": ui},"ev": 1}
    data_免费装扮箱 = {"req": "V313","e": {"ad": "0", "f": "2", "lt": "1", "n": "10", "pi": pi, "sk": sk, "ui": ui, "t": "4"},"ev": 1}
    print("请选择要抽取的箱子：")
    print("1. 白箱188")
    print("2. 紫箱688")
    print("3. 橙箱2888")
    print("4. 免费白箱10连(一天一次)")
    print("5. 免费紫箱10连(三天一次)")
    print("6. 免费橙箱单抽(一天两次)")
    print("7. 免费装扮10连(三天一次)")
    选择 = input("输入数字选择箱子：").strip()
    if 选择 == "1":
        箱子 = 白箱188
        print("正在抽取188宝箱10连...")
    elif 选择 == "2":
        箱子 = 紫箱688
        print("正在抽取688宝箱10连...")
    elif 选择 == "3":
        箱子 = 橙箱2888
        print("正在抽取2888宝箱10连...")
    elif 选择 == "4":
        箱子 = data_免费白箱
        print("正在抽取免费白箱10连...")
    elif 选择 == "5":
        箱子 = data_免费紫箱
        print("正在抽取免费紫箱10连...")
    elif 选择 == "6":
        箱子 = data_免费橙箱
        print("正在抽取免费橙箱单抽...")
    elif 选择 == "7":
        箱子 = data_免费装扮箱
        print("正在抽取免费装扮10连...")
    else:
        print("输入错误，请重新选择")
        return

    suc, r = send_加密发送_解密响应(箱子)
    total_rewards = {}
    if suc:
        if 'bl' in r:
            for item in r['bl']:
                代码 = str(item['i'])
                数量 = item.get('q', 0)
                if 选择 == "7":
                    装扮名称 = 植物装扮字典.get(代码, None)
                    装扮碎片 = 植物装扮碎片字典.get(代码, None)
                    if 装扮名称:
                        reward_name = f"植物{装扮名称}"
                        print(f"抽到了植物：{装扮名称} x {数量}")
                    elif 装扮碎片:
                        reward_name = 装扮碎片
                        print(f"抽到了 {装扮碎片} x {数量}")
                    else:
                        reward_name = f"未知({代码})"
                        print(f"代码：{代码}，数量：{数量}")
                else:
                    植物名称 = 植物字典.get(代码, None)
                    碎片名称 = 植物碎片字典.get(代码, None)
                    if 植物名称:
                        reward_name = f"植物{植物名称}"
                        print(f"抽到了植物：{植物名称} x {数量}")
                    elif 碎片名称:
                        reward_name = 碎片名称
                        print(f"抽到了 {碎片名称} x {数量}")
                    else:
                        reward_name = f"未知({代码})"
                        print(f"代码：{代码}，数量：{数量}")
                total_rewards[reward_name] = total_rewards.get(reward_name, 0) + 数量
        if 'p' in r and 'fg' in r['p']:
            钻石 = r['p']['fg']
            print(f"当前钻石数量: {钻石}💎")
        if 'p' in r and 'uk' in r['p']:
            uk = r['p']['uk']
            print(f"当前UK: {uk}")
    else:
        print("请求失败，未获取箱子结果")
    
    print("抽箱操作结束")
    print("本次累计获得奖励：")
    if total_rewards:
        for reward, total_qty in total_rewards.items():
            print(f"{reward} x {total_qty}")
    else:
        print("未获得任何奖励")
#===========================转基因======================
def make_转基因():
    碎片分类 = make_查询碎片()
    if not 碎片分类:
        return

    print("你要什么品质的碎片用来合成：")
    for i, 品质 in enumerate(碎片分类.keys(), 1):
        print(f"{i}. {品质}")

    品质选择 = input("输入数字选择品质：")
    try:
        品质选择 = int(品质选择)
        选择的品质 = list(碎片分类.keys())[品质选择 - 1]
    except (ValueError, IndexError):
        print("无效的选择，请重新选择")
        return

    碎片列表 = 碎片分类[选择的品质]
    if not 碎片列表:
        print(f"没有找到{选择的品质}品质的碎片")
        return

    print(f"请选择两个{选择的品质}品质的碎片：")
    for i, (代码, 名称, 数量) in enumerate(碎片列表, 1):
        print(f"{i}. {名称}")

    碎片选择1 = input("请选择第一种碎片：")
    碎片选择2 = input("请选择第二种碎片：")
    碎片选择3 = input("请选择第三种碎片(输入0不选)：")
    碎片选择4 = input("请选择第四种碎片(输入0不选)：")
    碎片选择5 = input("请选择第五种碎片(输入0不选)：")
    num = 0
    try:
        碎片选择1 = int(碎片选择1)
        碎片选择2 = int(碎片选择2)
        碎片选择3 = int(碎片选择3)
        碎片选择4 = int(碎片选择4)
        碎片选择5 = int(碎片选择5)
        碎片1 = 碎片列表[碎片选择1 - 1][0] if 碎片选择1 != 0 else 0
        碎片2 = 碎片列表[碎片选择2 - 1][0] if 碎片选择2 != 0 else 0
        碎片3 = 碎片列表[碎片选择3 - 1][0] if 碎片选择3 != 0 else 0
        碎片4 = 碎片列表[碎片选择4 - 1][0] if 碎片选择4 != 0 else 0
        碎片5 = 碎片列表[碎片选择5 - 1][0] if 碎片选择5 != 0 else 0
    except (ValueError, IndexError):
        print("无效的选择，请重新选择")
        return

    合成次数 = input("请输入合成次数：")
    try:
        合成次数 = int(合成次数)
    except ValueError:
        print("无效的输入，请重新选择")
        return

    for _ in range(合成次数):
        转基因 = {"req": "V323", "e": {"ad": "0", "l": [碎片1, 碎片2, 碎片3, 碎片4, 碎片5], "pi": pi, "sk": sk, "t": "0", "ui": ui}, "ev": 1}
        suc, r = send_加密发送_解密响应(转基因)
        if suc:
            if 'gl' in r:
                for item in r['gl']:
                    碎片代码 = item['i']
                    碎片数量 = item['q']
                    碎片名称 = 植物碎片字典.get(str(碎片代码), f"未知碎片({碎片代码})")
                    碎片品质 = 碎片品质字典.get(str(碎片代码), "白")
                    碎片颜色 = 碎片颜色字典.get(碎片品质, "\033[97m")
                    num+=1
                    print("第" + str(num) + "转基因   " + f"获得了 [{碎片颜色}{碎片品质}\033[0m] {碎片名称} x {碎片数量}\033[0m")
        else:
            print("转基因请求发送失败，响应如下：")
#===========================红色挂件======================
def make_红色挂件():
    挂件名称 = [
        "紫手套", "红蜡烛", "白蜡烛", "太阳锅盔", "月亮锅盔",
        "公主冰冠", "女王冰冠", "牛仔手套", "聚能电池", "节能电池",
        "强效杀虫剂", "杀虫剂", "大爆竹", "爆竹", "小时钟",
        "加速时钟", "警用电击棍", "电击棍", "止痛剂", "止疼片",
        "金属弹弓", "木质弹弓", "魔法书", "高级魔法书", "阳光齿轮",
        "时光胶囊", "降魔披风", "糖果篮子", "全部红色挂件"
    ]
    挂件选项 = [
       'super_clock', 'super_clock_1', 'super_clock_2', 'super_clock_3',
       'super_clock_4', 'super_clock_5', 'super_clock_6', 'super_clock_7',
       'super_clock_8', 'super_clock_9', 'super_clock_10', 'super_clock_11',
       'super_clock_12', 'super_clock_13', 'super_clock_14', 'super_clock_15',
       'super_clock_16', 'super_clock_17', 'painkiller_1', 'painkiller_2',
       'slingshot_1', 'slingshot_2', 'magic_book_1', 'magic_book_2',
       'sun_gear_1', 'travel_together_1', 'hero_cape_1', 'candy_basket', '全部红色挂件'
    ]
    上位挂件对应的实际名称 = [
       'super_clock', 'super_clock_1', 'super_clock_2', 'super_clock_3',
       'super_clock_4', 'super_clock_5', 'super_clock_6', 'super_clock_7',
       'super_clock_8', 'super_clock_9', 'super_clock_10', 'super_clock_11',
       'super_clock_12', 'super_clock_13', 'super_clock_14', 'super_clock_15',
       'super_clock_16', 'super_clock_17', 'painkiller_1', 'painkiller_2',
       'slingshot_1', 'slingshot_2', 'magic_book_1', 'magic_book_2',
       'sun_gear_1', 'travel_together_1', 'hero_cape_1', 'candy_basket'
    ]
    
    print("请选择要刷取的挂件：")
    LEFT_WIDTH = 17 
    total = len(挂件名称)
    for i in range(0, total, 3):
        line_parts = []
        for j in range(3):
            idx = i + j
            if idx < total:
                seq = f"{idx+1:2d}. {挂件名称[idx]}"
                line_parts.append(ljust_visual(seq, LEFT_WIDTH))
            else:
                line_parts.append("")
        print("".join(line_parts))
    
    choice = input("\n请输入挂件序号（刷取多个用空格隔开，直接回车退出）：").split()
    if not choice:
        return
    挂件数量_dict = {}
    for 选择的序号 in choice:
        if 选择的序号 == '29':
            try:
                数量 = int(input("请输入全部挂件的数量："))
            except Exception as e:
                print("数量输入错误！")
                return
            for 实际名称 in 上位挂件对应的实际名称:
                挂件数量_dict[实际名称] = 数量
        else:
            try:
                index_num = int(选择的序号)
            except ValueError:
                print("挂件序号输入错误！")
                return
            if not (1 <= index_num <= total):
                print("挂件序号超出范围！")
                return
            挂件 = 挂件选项[index_num - 1]
            对应的挂件名称 = 挂件名称[index_num - 1]
            try:
                数量 = int(input(f"请输入 {对应的挂件名称} 的刷取数量："))
            except Exception as e:
                print("数量输入错误！")
                return
            挂件数量_dict[挂件] = 数量

    class 挂件管理器:
        def __init__(self):
            self.url = 'http://cloudpvz2android.ditwan.cn/index.php'
            self.headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        def 构造替换文本(self, paci, pacid, l, 挂件数量_dict):
            替换文本_list = []
            for 挂件, 数量 in 挂件数量_dict.items():
                单个挂件文本 = [f'{{"paci":{paci},"pact":"{挂件}","pacid":{pacid},"l":{l}}}' for _ in range(数量)]
                替换文本_list.extend(单个挂件文本)
            return ",".join(替换文本_list)
        def gzip压缩(self, 文本: str) -> str:
            try:
                文本 = f'"{文本}"'
                文本字节 = 文本.encode('utf-8')
                with io.BytesIO() as buffer:
                    with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=9) as gz_file:
                        gz_file.write(文本字节)
                    压缩字节 = buffer.getvalue()
                压缩文本 = base64.b64encode(压缩字节).decode('utf-8')
                return 压缩文本.replace('+', '-').replace('/', '_').replace('=', ',')
            except Exception as e:
                raise Exception(f"Gzip压缩失败: {e}")
        def base64编码(self, 文本: str) -> str:
            return base64.b64encode(文本.encode('utf-8')).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', ',')
        def md5加密(self, 文本: str) -> str:
            return hashlib.md5(文本.encode('utf-8')).hexdigest()
        def 处理解密结果_初始为零(self, 解密文本: str, pi1: str, l, 挂件数量_dict):
            替换文本 = self.构造替换文本(-1, pi1, l, 挂件数量_dict)
            被替换文本 = '"pasi":[]'
            if 被替换文本 in 解密文本:
                return 解密文本.replace(被替换文本, f'"pasi":[{替换文本}]', 1)
            else:
                print("'pasi'数组为空，未找到匹配文本")
                return 解密文本
        def 处理解密结果_初始不为零(self, 解密文本: str, 挂件数量_dict):
            pattern = r'{"paci":(-?\d+),"pact":"(.*?)","pacid":(\d+),"l":(\d+)}'
            匹配结果 = re.findall(pattern, 解密文本)
            if 匹配结果:
                有效匹配 = [匹配 for 匹配 in 匹配结果 if int(匹配[3]) > 0]
                if 有效匹配:
                    有效匹配.sort(key=lambda x: int(x[3]), reverse=True)
                    最大匹配 = 有效匹配[0]
                else:
                    最大匹配 = random.choice(匹配结果)
                paci, pact, pacid, l = 最大匹配
                被替换文本 = f'{{"paci":{paci},"pact":"{pact}","pacid":{pacid},"l":{l}}}'
                替换文本 = self.构造替换文本(paci, pacid, l, 挂件数量_dict)
                if 被替换文本 in 解密文本:
                    return 解密文本.replace(被替换文本, 替换文本, 1)
                else:
                    print(f"未找到匹配的文本: {被替换文本}")
                    return 解密文本
            else:
                print("没有匹配到任何数据")
                return 解密文本
        def base64解密(self, input_data: str) -> str:
            try:
                input_data = input_data.replace('-', '+').replace('_', '/').replace(',', '=')
                if len(input_data) % 4:
                    input_data += '=' * (4 - len(input_data) % 4)
                return base64.b64decode(input_data).decode('utf-8')
            except Exception as e:
                print(f"Base64解密失败: {e}")
                return ""
        def 获取解密数据(self, url: str, headers: dict, data: dict) -> dict:
            加密数据 = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
            response = requests.post(url, headers=headers, data=加密数据.encode('utf-8'))
            if response.status_code == 200:
                解密数据 = CNNetwork.decrypt(response.text)
                try:
                    return json.loads(解密数据)
                except json.JSONDecodeError:
                    print(f"JSON解码失败，响应内容: {response.text}")
                    return {}
            else:
                print(f"请求失败，状态码: {response.status_code}")
                return {}
        def 构建请求数据(self, 用户S: str, 处理后的文本: str, pi: str, sk: str) -> str:
            重新编码文本 = self.base64编码(处理后的文本)
            pr = self.gzip压缩(重新编码文本)
            if pr is not None:
                数据 = pr.replace('+', '-').replace('/', '_').replace('=', ',')
                md5值 = self.md5加密(处理后的文本)
                构建206 = {
                    "req": "V206",
                    "e": {
                        "m": md5值,
                        "pi": pi,
                        "pr": 数据,
                        "s": 用户S,
                        "sk": sk,
                        "ui": ui
                    },
                    "ev": 1
                }
                return CNNetwork.encrypt(json.dumps(构建206, separators=(',', ':')))
            else:
                return ""
        def 查询挂件数量(self, url: str, headers: dict, data: dict, pi: str, sk: str) -> int:
            try:
                解码数据 = self.获取解密数据(url, headers, data)
                用户p = 解码数据.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
                用户p解密 = self.base64解密(用户p)
                pattern = r'{"paci":(-?\d+),"pact":"(.*?)","pacid":(\d+),"l":(\d+)}'
                匹配结果 = re.findall(pattern, 用户p解密)
                return len(匹配结果)
            except AttributeError:
                print("获取挂件数量时发生属性错误，跳过该账号")
                return 0
        def 检查是否替换成功(self, 初始挂件数量: int, url: str, headers: dict, data: dict, pi: str, sk: str) -> str:
            当前挂件数量 = 0
            for 尝试次数 in range(5):
                import time
                time.sleep(1)
                try:
                    当前挂件数量 = self.查询挂件数量(url, headers, data, pi, sk)
                    print(f"正在获取... {尝试次数 + 1}: 当前挂件数量: {当前挂件数量}")
                    if 当前挂件数量 > 初始挂件数量:
                        return f"初始挂件数量为{初始挂件数量} 当前挂件数量{当前挂件数量} 修改成功,请重新进入游戏选择云端存档"
                except Exception as e:
                    print(f"检查是否替换成功时发生错误: {e}，跳过该账号")
                    return ""
            return f"初始挂件数量为{初始挂件数量} 当前挂件数量{当前挂件数量} 修改失败"
        def main(self, pi, sk, 挂件数量_dict):
            try:
                data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                初始挂件数量 = self.查询挂件数量(self.url, self.headers, data, pi, sk)
                print(f"初始挂件数量: {初始挂件数量}")
                if 初始挂件数量 == 0:
                    获取挂件id_request = {
                        "req": "V254",
                        "e": {"oi": "22075", "pi": pi, "sk": sk, "ui": ui},
                        "ev": 1
                    }
                    获取挂件响应 = self.获取解密数据(self.url, self.headers, 获取挂件id_request)
                    print(获取挂件响应)
                    pi1 = 获取挂件响应.get("e", {}).get("d", {}).get("pe", {}).get("pi1", "")
                    l = 获取挂件响应.get("e", {}).get("d", {}).get("pe", {}).get("l", 0)
                    解码数据 = self.获取解密数据(self.url, self.headers, data)
                    用户p = 解码数据.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
                    用户p解密 = self.base64解密(用户p)
                    处理后的文本 = self.处理解密结果_初始为零(用户p解密, pi1, l, 挂件数量_dict)
                else:
                    解码_data = self.获取解密数据(self.url, self.headers, data)
                    用户p = 解码_data.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
                    用户p解密 = self.base64解密(用户p)
                    处理后的文本 = self.处理解密结果_初始不为零(用户p解密, 挂件数量_dict)
                响应数据 = self.构建请求数据(解码_data.get("e", {}).get("d", {}).get("pr", {}).get("s", ""), 处理后的文本, pi, sk)
                if 响应数据:
                    response = requests.post(self.url, headers=self.headers, data=响应数据.encode('utf-8'))
                    if response.status_code == 200:
                        print("挂件刷取成功")
                    else:
                        print(f"挂件刷取失败，状态码:{response.status_code}")
                return self.检查是否替换成功(初始挂件数量, self.url, self.headers, data, pi, sk)
            except Exception as e:
                print(f"处理该账号时发生错误: {e}，跳过该账号")
                return ""
    管理器 = 挂件管理器()
    结果 = 管理器.main(pi, sk, 挂件数量_dict)
    print(f"结果:{结果}")
#===========================聚屎盆======================
def make_聚宝盆():
    for i in range(1, 6):
        data = {"req": "V868", "e": {"pi": pi, "sk": sk, "ti": str(1000 + i), "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "聚宝盆第{}个任务领取".format(i))
        make_聚宝盆收获()
#===========================幸运宝藏======================
def make_幸运宝藏():
    d_ = {"req": "V303", "e": {"al": [{"id": 10889, "abi": 0, "type": 1, "config_version": 1}], "ci": "93", "cs": "0", "pack": "", "pi": pi, "sk": sk, "ui": ui, "v": newest_version}, "ev": 1}
    suc, r = send_加密发送_解密响应(d_)
    if not suc:
        print(f"进入幸运宝藏失败")
        return

    print("进入幸运宝藏成功")
    x = 0 
    for i in range(1, 4):
        data = {"req": "V507", "e": {"pi": pi, "sk": sk, "t": str(1000 + i), "ui": ui}, "ev": 1}
        suc, r = send_加密发送_解密响应(data)
        if suc and r:
            x += 1
            if 'gift' in r:
                for gift_item in r['gift']:
                    for item in gift_item:
                        item_id = item.get('i')
                        item_quantity = item.get('q')
                        if item_id == '3008':  # 坤吧钻石
                            print(f"{LIGHTCYAN}获得钻石{RESET} {item_quantity}💎")
                        elif item_id in 植物碎片字典:
                            plant_name = 植物碎片字典[item_id]
                            print(f"{LIGHTGREEN}获得植物碎片{RESET} {plant_name} x{item_quantity}")
                        elif item_id in 道具字典:
                            item_name = 道具字典[item_id]
                            print(f"获得 {LIGHTYELLOW}{item_name}{RESET} x{item_quantity}")
                        elif item_id in 植物装扮碎片字典:
                            装扮 = 植物装扮碎片字典[item_id]
                            print(f"{LIGHTPINK}获得装扮碎片{RESET} {装扮} x{item_quantity}")
            else:
                print(f"幸运宝藏{i}响应中没有gift字段")
        else:
            print(f"幸运宝藏第{i}个宝箱领取失败")
#===========================42号平行宇宙======================
def make_平行宇宙普通():
    for i in range(1, 8):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "", "type": "0", "ui": ui, "win": "1",
                      "world": "uncharted_no42_universe"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过41号平行宇宙普通第{}关".format(i))
def make_平行宇宙困难():
    for i in range(1, 8):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "", "type": "1", "ui": ui, "win": "1",
                      "world": "uncharted_no42_universe"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过41号平行宇宙困难第{}关".format(i))

def make_平行宇宙无限刷币():
    for i in range(1,99999999):
        data无限 = {"req": "V411",
                "e": {"eln": 100,"level": 6, "pi": pi, "sk": sk, "tgt": "", "type": "1", "ui": ui, "win": "1",
                      "world": "uncharted_no42_universe"}, "ev": 1}

        send_加密发送_拼接提示(data无限, "刷币第{}次".format(i))
def make_蓝宝石():
    for i in range(24):
        data_蓝宝石 = {"req":"V273","e":{"bi":"0","d":[{"id":0,"t":19.374435,"l":0.0,"k":1}],"pi":pi,"sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data_蓝宝石,f"蓝宝石第{i+1}个")
def make_蓝宝石抽奖():
    total_rewards = {}
    for i in range(24):
        data_蓝宝石抽奖 = {"req": "V347", "e": {"lct": "1", "pi": pi, "sk": sk, "t": "10799", "ui": ui}, "ev": 1}
        _, r = send_加密发送_解密响应(data_蓝宝石抽奖)
        b = r.get("b", {})
        il = r.get("il", [])
        item_code = str(b.get("i"))
        item_qty = b.get("q", 0)
        if item_code in 道具字典:
            item_name = 道具字典[item_code]
        elif item_code in 植物碎片字典:
            item_name = 植物碎片字典[item_code]
        else:
            item_name = str(item_code)
        blue_crystal_qty = il[0]["q"] if il and "q" in il[0] else 0
        print(f"第{i+1}次抽奖：获得 {item_name} x{item_qty}，蓝水晶数量：{blue_crystal_qty}")
        total_rewards[item_name] = total_rewards.get(item_name, 0) + item_qty

    print("累计获得奖励：")
    for reward, qty in total_rewards.items():
        print(f"{reward} x{qty}")
#===========================戴夫厨房======================
def make_戴夫厨房():
    for i in range(5):
        data_666 = {"req":"V712","e":{"key":str(i - 1),"pi":pi,"sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data_666,f"戴夫厨房任务第{i+1}个")
    for i in range(6):
        data = {"req":"V711","e":{"key":"6","pi":pi,"sk":sk,"ui":ui},"ev":1}
        send_加密发送_拼接提示(data,f"戴夫厨房钻石第{i+1}个")
#===========================黄瓜======================
def make_黄瓜():
    class 黄瓜管理器:
        def __init__(self):
            self.url = 'http://cloudpvz2android.ditwan.cn/index.php'
            self.headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
            
        def 构造替换文本(self, 黄瓜数量):
            return f'{{"n":"poweruptacticalcuke","i":{黄瓜数量}}}'
            
        def gzip压缩(self, 文本: str) -> str:
            try:
                文本 = f'"{文本}"'
                文本字节 = 文本.encode('utf-8')
                with io.BytesIO() as buffer:
                    with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=9) as gz_file:
                        gz_file.write(文本字节)
                    压缩字节 = buffer.getvalue()
                压缩文本 = base64.b64encode(压缩字节).decode('utf-8')
                return 压缩文本.replace('+', '-').replace('/', '_').replace('=', ',')
            except Exception as e:
                raise Exception(f"Gzip压缩失败: {e}")
                
        def base64编码(self, 文本: str) -> str:
            return base64.b64encode(文本.encode('utf-8')).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', ',')
            
        def md5加密(self, 文本: str) -> str:
            return hashlib.md5(文本.encode('utf-8')).hexdigest()
            
        def 处理解密结果(self, 解密文本: str, 黄瓜数量: int):
            pattern = r'"pr":\[(.*?)\]'
            替换文本 = self.构造替换文本(黄瓜数量)
            if '"pr":[]' in 解密文本:
                return 解密文本.replace('"pr":[]', f'"pr":[{替换文本}]')
            匹配 = re.search(pattern, 解密文本)
            if 匹配:
                return 解密文本.replace(匹配.group(0), f'"pr":[{替换文本}]')
            return 解密文本
            
        def base64解密(self, input_data: str) -> str:
            try:
                input_data = input_data.replace('-', '+').replace('_', '/').replace(',', '=')
                if len(input_data) % 4:
                    input_data += '=' * (4 - len(input_data) % 4)
                return base64.b64decode(input_data).decode('utf-8')
            except Exception as e:
                print(f"Base64解密失败: {e}")
                return ""
                
        def 获取解密数据(self, url: str, headers: dict, data: dict) -> dict:
            加密数据 = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
            response = requests.post(url, headers=headers, data=加密数据.encode('utf-8'))
            if response.status_code == 200:
                解密数据 = CNNetwork.decrypt(response.text)
                try:
                    return json.loads(解密数据)
                except json.JSONDecodeError:
                    print(f"JSON解码失败，响应内容: {response.text}")
                    return {}
            else:
                print(f"请求失败，状态码: {response.status_code}")
                return {}
                
        def 获取当前黄瓜数量(self, url: str, headers: dict, data: dict):
            try:
                解码数据 = self.获取解密数据(url, headers, data)
                用户p = 解码数据.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
                用户p解密 = self.base64解密(用户p)
                pattern = r'"n":"poweruptacticalcuke","i":(\d+)'
                匹配 = re.search(pattern, 用户p解密)
                if 匹配:
                    return int(匹配.group(1))
                return 0
            except Exception as e:
                print(f"获取黄瓜数量时发生错误: {e}")
                return 0
                
        def 构建请求数据(self, 用户S: str, 处理后的文本: str, pi: str, sk: str) -> str:
            重新编码文本 = self.base64编码(处理后的文本)
            pr = self.gzip压缩(重新编码文本)
            if pr is not None:
                数据 = pr.replace('+', '-').replace('/', '_').replace('=', ',')
                md5值 = self.md5加密(处理后的文本)
                构建206 = {
                    "req": "V206",
                    "e": {
                        "m": md5值,
                        "pi": pi,
                        "pr": 数据,
                        "s": 用户S,
                        "sk": sk,
                        "ui": ui
                    },
                    "ev": 1
                }
                return CNNetwork.encrypt(json.dumps(构建206, separators=(',', ':')))
            else:
                return ""
                
        def main(self, pi, sk, 黄瓜数量):
            try:
                data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                初始黄瓜数量 = self.获取当前黄瓜数量(self.url, self.headers, data)
                print(f"==================================================== \n当前黄瓜数量: {初始黄瓜数量}")
                
                print("请输入要修改的黄瓜数量:")
                黄瓜数量 = int(input())

                
                解码数据 = self.获取解密数据(self.url, self.headers, data) 
                用户p = 解码数据.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
                用户p解密 = self.base64解密(用户p)
                处理后的文本 = self.处理解密结果(用户p解密, 黄瓜数量)
                
                响应数据 = self.构建请求数据(解码数据.get("e", {}).get("d", {}).get("pr", {}).get("s", ""), 处理后的文本, pi, sk)
                if 响应数据:
                    response = requests.post(self.url, headers=self.headers, data=响应数据.encode('utf-8'))
                    if response.status_code == 200:
                        print("黄瓜数量修改成功")
                        return f"\033[92m初始黄瓜数量为{初始黄瓜数量} 已修改为{黄瓜数量}个黄瓜,请重新进入游戏选择云端存档\033[0m"
                    else:
                        print(f"修改失败，状态码:{response.status_code}")
                        return f"\033[91m修改失败\033[0m"
            except Exception as e:
                print(f"处理该账号时发生错误: {e}")
                return f"\033[91m修改失败: {str(e)}\033[0m"
                
    管理器 = 黄瓜管理器()
    结果 = 管理器.main(pi, sk, 0)  
    print(f"   \033[95m结果\033[0m\n结果:{结果}\n====================================================")
#===========================刷金币======================
def make_金币():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        加密数据 = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=加密数据.encode('utf-8'))
        if response.status_code != 200:
            print("金币注入失败")
            return
        解密数据 = CNNetwork.decrypt(response.text)
        res = json.loads(解密数据)
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - len(p_decode) % 4)
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
        
        def to_int32(x):
            x = x & 0xFFFFFFFF
            return x if x < 0x80000000 else x - 0x100000000

        def encrypt_number(data: int) -> int:
            res = ((data ^ 13) << 13) | ((data & 0xFFFFFFFF) >> 19)
            return to_int32(res)
        
        while True:
            try:
                gold = int(input("请输入注入金币数量（32位整数）："))
                encrypted_gold = encrypt_number(gold)
                break
            except ValueError:
                print("请输入有效整数！")
        
        p_json["sd"]["c"] = encrypted_gold
        
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5值 = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8')\
                     .replace('+', '-').replace('/', '_').replace('=', ',')
        req206 = {
            "req": "V206",
            "e": {
                "m": md5值,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        加密数据2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=加密数据2.encode('utf-8'))
        if response2.status_code == 200:
            print("金币修注入成功，请重新进入游戏选择云端存档")
        else:
            print("金币注入失败")
    except Exception:
        print("金币注入失败")
#===========================豌豆共生======================
def make_豌豆共生():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        加密数据 = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=加密数据.encode('utf-8'))
        if response.status_code != 200:
            print("豌豆共生注入失败")
            return
        解密数据 = CNNetwork.decrypt(response.text)
        res = json.loads(解密数据)
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - len(p_decode) % 4)
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
        psla_value = p_json.get("sd", {}).get("psla", [])
        found = False
        for item in psla_value:
            if item.get("icpi") == 428:
                item["icl"] = 5
                found = True
                break
        if not found:
            psla_value.append({"icpi": 428, "icl": 5})
        new_psla_value = []
        count = 0
        for item in psla_value:
            if item.get("icpi") == 428 and item.get("icl") == 5:
                if count == 0:
                    new_psla_value.append(item)
                    count += 1
            else:
                new_psla_value.append(item)
        p_json["sd"]["psla"] = new_psla_value
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5值 = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', ',')
        req206 = {
            "req": "V206",
            "e": {
                "m": md5值,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        加密数据2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=加密数据2.encode('utf-8'))
        if response2.status_code == 200:
            print("豌豆共生注入成功，请重新进入游戏选择云端存档手动打开共生开关")
        else:
            print("豌豆共生注入失败")
    except Exception:
        print("豌豆共生注入失败")
#===========================全头像======================
def make_全头像():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        加密数据 = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=加密数据.encode('utf-8'))
        if response.status_code != 200:
            print("全头像注入失败")
            return
        解密数据 = CNNetwork.decrypt(response.text)
        res = json.loads(解密数据)
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - len(p_decode) % 4)
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
        p_json["sd"]["unlockhs"] = list(range(25001, 25700))
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5值 = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', ',')
        req206 = {
            "req": "V206",
            "e": {
                "m": md5值,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        加密数据2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=加密数据2.encode('utf-8'))
        if response2.status_code == 200:
            print("全头像注入成功，请重新进入游戏选择云端存档")
        else:
            print("全头像注入失败")
    except Exception:
        print("全头像注入失败")

def make_注入世界():
    try:
        # 获取当前用户数据
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        encrypt_data = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=encrypt_data.encode('utf-8'))
        if response.status_code != 200:
            print("注入失败")
            return
        decrypt_data = CNNetwork.decrypt(response.text)
        res = json.loads(decrypt_data)
        # 解析返回数据中的用户信息
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - (len(p_decode) % 4))
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
    
        # 根据用户输入构造注入数据
        choice = input("请输入1注入满星世界，输入2注入初始世界: ").strip()
        if choice == "1":
            wmed_value = [
                {"w":1,"e":[{"i":6,"h":1},{"i":1,"h":1},{"i":2,"h":1},{"i":3,"h":1},{"i":4,"h":1}],"r":"false"},
                {"w":2,"e":[{"i":1,"h":1},{"i":12,"h":1},{"i":2,"h":1},{"i":46,"h":1},{"i":3,"h":1},
                             {"i":15,"h":1},{"i":40,"h":1},{"i":7,"h":1},{"i":6,"h":1},{"i":5,"h":1},
                             {"i":35,"h":1},{"i":14,"h":1},{"i":8,"h":1},{"i":9,"h":1},{"i":10,"h":1},
                             {"i":4,"h":1},{"i":20,"h":1},{"i":22,"h":1},{"i":84,"h":1}],"r":"false"},
                {"w":3,"e":[{"i":40,"h":1},{"i":1,"h":1},{"i":11,"h":1},{"i":2,"h":1},{"i":64,"h":1},
                             {"i":3,"h":1},{"i":4,"h":1},{"i":5,"h":1},{"i":6,"h":1},{"i":13,"h":1},
                             {"i":7,"h":1},{"i":8,"h":1},{"i":9,"h":1},{"i":16,"h":1},{"i":10,"h":1},
                             {"i":48,"h":1},{"i":49,"h":1},{"i":50,"h":1},{"i":52,"h":1},{"i":53,"h":1},
                             {"i":54,"h":1},{"i":55,"h":1},{"i":56,"h":1},{"i":57,"h":1},{"i":58,"h":1},
                             {"i":59,"h":1},{"i":60,"h":1},{"i":61,"h":1},{"i":62,"h":1},{"i":63,"h":1}],"r":"false"},
                {"w":4,"e":[{"i":26,"h":1},{"i":1,"h":1},{"i":11,"h":1},{"i":2,"h":1},{"i":111,"h":1},
                             {"i":3,"h":1},{"i":4,"h":1},{"i":12,"h":1},{"i":5,"h":1},{"i":6,"h":1},
                             {"i":7,"h":1},{"i":8,"h":1},{"i":9,"h":1},{"i":13,"h":1},{"i":10,"h":1},
                             {"i":84,"h":1},{"i":85,"h":1},{"i":86,"h":1},{"i":87,"h":1},{"i":88,"h":1},
                             {"i":89,"h":1},{"i":90,"h":1},{"i":91,"h":1},{"i":92,"h":1},{"i":93,"h":1},
                             {"i":94,"h":1},{"i":95,"h":1},{"i":96,"h":1},{"i":97,"h":1},{"i":110,"h":1}],"r":"false"},
                {"w":5,"e":[{"i":44,"h":1},{"i":1,"h":1},{"i":2,"h":1},{"i":85,"h":1},{"i":3,"h":1},
                             {"i":11,"h":1},{"i":40,"h":1},{"i":7,"h":1},{"i":6,"h":1},{"i":76,"h":1},
                             {"i":5,"h":1},{"i":35,"h":1},{"i":8,"h":1},{"i":9,"h":1},{"i":10,"h":1},
                             {"i":4,"h":1},{"i":20,"h":1},{"i":22,"h":1},{"i":19,"h":1},{"i":24,"h":1},
                             {"i":25,"h":1},{"i":26,"h":1},{"i":36,"h":1},{"i":37,"h":1},{"i":42,"h":1},
                             {"i":29,"h":1},{"i":30,"h":1},{"i":31,"h":1},{"i":84,"h":1}],"r":"false"},
                {"w":14,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":12,"h":1},{"i":13,"h":1},
                              {"i":16,"h":1},{"i":14,"h":1},{"i":15,"h":1},{"i":17,"h":1},
                              {"i":18,"h":1},{"i":19,"h":1},{"i":21,"h":1},{"i":22,"h":1},
                              {"i":24,"h":1},{"i":34,"h":1},{"i":25,"h":1},{"i":27,"h":1},
                              {"i":29,"h":1},{"i":30,"h":1},{"i":32,"h":1},{"i":33,"h":1},
                              {"i":35,"h":1},{"i":36,"h":1},{"i":37,"h":1},{"i":38,"h":1},
                              {"i":39,"h":1},{"i":40,"h":1},{"i":41,"h":1},{"i":42,"h":1},
                              {"i":50,"h":1},{"i":51,"h":1},{"i":52,"h":1}],"r":"false"},
                {"w":6,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":35,"h":1},{"i":41,"h":1},
                             {"i":69,"h":1},{"i":42,"h":1},{"i":43,"h":1},{"i":44,"h":1},
                             {"i":46,"h":1},{"i":47,"h":1},{"i":48,"h":1},{"i":49,"h":1},
                             {"i":50,"h":1},{"i":37,"h":1},{"i":51,"h":1},{"i":52,"h":1},
                             {"i":53,"h":1},{"i":54,"h":1},{"i":55,"h":1},{"i":56,"h":1},
                             {"i":60,"h":1},{"i":61,"h":1},{"i":62,"h":1},{"i":63,"h":1},
                             {"i":64,"h":1},{"i":65,"h":1},{"i":66,"h":1},{"i":67,"h":1},
                             {"i":68,"h":1}],"r":"false"},
                {"w":8,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":35,"h":1},{"i":41,"h":1},
                             {"i":86,"h":1},{"i":42,"h":1},{"i":43,"h":1},{"i":40,"h":1},
                             {"i":44,"h":1},{"i":72,"h":1},{"i":46,"h":1},{"i":47,"h":1},
                             {"i":36,"h":1},{"i":48,"h":1},{"i":71,"h":1},{"i":49,"h":1},
                             {"i":73,"h":1},{"i":74,"h":1},{"i":75,"h":1},{"i":76,"h":1},
                             {"i":50,"h":1},{"i":77,"h":1},{"i":78,"h":1},{"i":79,"h":1},
                             {"i":80,"h":1},{"i":51,"h":1},{"i":52,"h":1},{"i":53,"h":1},
                             {"i":54,"h":1},{"i":68,"h":1}],"r":"false"},
                {"w":12,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":12,"h":1},{"i":13,"h":1},
                              {"i":14,"h":1},{"i":15,"h":1},{"i":17,"h":1},{"i":18,"h":1},
                              {"i":19,"h":1},{"i":20,"h":1},{"i":21,"h":1},{"i":22,"h":1},
                              {"i":24,"h":1},{"i":25,"h":1},{"i":26,"h":1},{"i":27,"h":1},
                              {"i":29,"h":1},{"i":30,"h":1},{"i":32,"h":1},{"i":33,"h":1},
                              {"i":34,"h":1},{"i":35,"h":1},{"i":36,"h":1},{"i":37,"h":1},
                              {"i":38,"h":1},{"i":39,"h":1},{"i":40,"h":1},{"i":41,"h":1},
                              {"i":42,"h":1}],"r":"false"},
                {"w":11,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":12,"h":1},{"i":13,"h":1},
                              {"i":59,"h":1},{"i":14,"h":1},{"i":15,"h":1},{"i":17,"h":1},
                              {"i":18,"h":1},{"i":19,"h":1},{"i":21,"h":1},{"i":22,"h":1},
                              {"i":24,"h":1},{"i":25,"h":1},{"i":27,"h":1},{"i":29,"h":1},
                              {"i":30,"h":1},{"i":32,"h":1},{"i":33,"h":1},{"i":61,"h":1},
                              {"i":34,"h":1},{"i":36,"h":1},{"i":37,"h":1},{"i":39,"h":1},
                              {"i":48,"h":1},{"i":40,"h":1},{"i":42,"h":1},{"i":43,"h":1},
                              {"i":45,"h":1},{"i":56,"h":1}],"r":"false"},
                {"w":17,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":12,"h":1},{"i":13,"h":1},
                              {"i":15,"h":1},{"i":16,"h":1},{"i":17,"h":1},{"i":18,"h":1},
                              {"i":19,"h":1},{"i":20,"h":1},{"i":21,"h":1},{"i":22,"h":1},
                              {"i":23,"h":1},{"i":24,"h":1},{"i":25,"h":1},{"i":26,"h":1},
                              {"i":27,"h":1},{"i":28,"h":1},{"i":29,"h":1},{"i":30,"h":1},
                              {"i":31,"h":1}],"r":"false"},
                {"w":7,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":35,"h":1},{"i":41,"h":1},
                             {"i":40,"h":1},{"i":42,"h":1},{"i":75,"h":1},{"i":43,"h":1},
                             {"i":45,"h":1},{"i":44,"h":1},{"i":46,"h":1},{"i":47,"h":1},
                             {"i":48,"h":1},{"i":49,"h":1},{"i":50,"h":1},{"i":51,"h":1},
                             {"i":52,"h":1},{"i":53,"h":1},{"i":73,"h":1},{"i":54,"h":1},
                             {"i":55,"h":1},{"i":58,"h":1},{"i":56,"h":1},{"i":60,"h":1},
                             {"i":61,"h":1},{"i":62,"h":1},{"i":74,"h":1},{"i":69,"h":1},
                             {"i":70,"h":1},{"i":71,"h":1},{"i":72,"h":1},{"i":68,"h":1}],"r":"false"},
                {"w":15,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":12,"h":1},{"i":13,"h":1},
                             {"i":16,"h":1},{"i":14,"h":1},{"i":15,"h":1},{"i":17,"h":1},
                             {"i":18,"h":1},{"i":19,"h":1},{"i":21,"h":1},{"i":22,"h":1},
                             {"i":24,"h":1},{"i":34,"h":1},{"i":25,"h":1},{"i":27,"h":1},
                             {"i":29,"h":1},{"i":30,"h":1},{"i":32,"h":1},{"i":33,"h":1},
                             {"i":35,"h":1},{"i":36,"h":1},{"i":37,"h":1},{"i":38,"h":1},
                             {"i":39,"h":1},{"i":40,"h":1},{"i":41,"h":1},{"i":42,"h":1}],"r":"false"},
                {"w":13,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":13,"h":1},{"i":75,"h":1},
                             {"i":14,"h":1},{"i":15,"h":1},{"i":17,"h":1},{"i":12,"h":1},
                             {"i":18,"h":1},{"i":19,"h":1},{"i":21,"h":1},{"i":26,"h":1},
                             {"i":22,"h":1},{"i":24,"h":1},{"i":25,"h":1},{"i":27,"h":1},
                             {"i":76,"h":1},{"i":29,"h":1},{"i":30,"h":1},{"i":32,"h":1},
                             {"i":33,"h":1},{"i":34,"h":1},{"i":36,"h":1},{"i":37,"h":1},
                             {"i":38,"h":1},{"i":39,"h":1},{"i":40,"h":1},{"i":41,"h":1},
                             {"i":43,"h":1},{"i":51,"h":1}],"r":"false"},
                {"w":16,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":12,"h":1},{"i":13,"h":1},
                             {"i":17,"h":1},{"i":14,"h":1},{"i":16,"h":1},{"i":15,"h":1},
                             {"i":18,"h":1},{"i":19,"h":1},{"i":22,"h":1},{"i":24,"h":1}],"r":"false"},
                {"w":9,"e":[{"i":11,"h":1},{"i":1,"h":1},{"i":35,"h":1},{"i":41,"h":1},
                             {"i":82,"h":1},{"i":42,"h":1},{"i":43,"h":1},{"i":44,"h":1},
                             {"i":72,"h":1},{"i":45,"h":1},{"i":46,"h":1},{"i":47,"h":1},
                             {"i":48,"h":1},{"i":71,"h":1},{"i":49,"h":1},{"i":73,"h":1},
                             {"i":74,"h":1},{"i":75,"h":1},{"i":76,"h":1},{"i":50,"h":1},
                             {"i":77,"h":1},{"i":78,"h":1},{"i":79,"h":1},{"i":80,"h":1},
                             {"i":51,"h":1},{"i":52,"h":1},{"i":53,"h":1},{"i":55,"h":1},
                             {"i":68,"h":1}],"r":"false"},
                {"w":10,"e":[{"i":44,"h":1},{"i":1,"h":1},{"i":88,"h":1},{"i":2,"h":1},
                             {"i":3,"h":1},{"i":86,"h":1},{"i":40,"h":1},{"i":7,"h":1},
                             {"i":6,"h":1},{"i":90,"h":1},{"i":5,"h":1},{"i":35,"h":1},
                             {"i":91,"h":1},{"i":8,"h":1},{"i":9,"h":1},{"i":10,"h":1},
                             {"i":4,"h":1},{"i":20,"h":1},{"i":85,"h":1},{"i":22,"h":1},
                             {"i":19,"h":1},{"i":24,"h":1},{"i":25,"h":1},{"i":26,"h":1},
                             {"i":89,"h":1},{"i":36,"h":1},{"i":37,"h":1},{"i":42,"h":1},
                             {"i":29,"h":1},{"i":30,"h":1}],"r":"false"}
            ]
        elif choice == "2":
            wmed_value = [
                {"w":1,"e":[{"i":6,"h":0},{"i":1,"h":0},{"i":2,"h":0},{"i":3,"h":0},{"i":4,"h":0}],"r":False},
                {"w":2,"e":[{"i":1,"h":0},{"i":12,"h":0},{"i":2,"h":0},{"i":46,"h":0},{"i":3,"h":0},
                             {"i":15,"h":0},{"i":40,"h":0},{"i":7,"h":0},{"i":6,"h":0},{"i":5,"h":0},
                             {"i":35,"h":0},{"i":8,"h":0},{"i":14,"h":0},{"i":9,"h":0},{"i":10,"h":0},
                             {"i":4,"h":0},{"i":20,"h":0},{"i":22,"h":0},{"i":84,"h":1}],"r":False},
                {"w":3,"e":[{"i":40,"h":0},{"i":1,"h":0},{"i":11,"h":0},{"i":2,"h":0},{"i":64,"h":0},
                             {"i":3,"h":0},{"i":4,"h":0},{"i":5,"h":0},{"i":6,"h":0},{"i":13,"h":0},
                             {"i":7,"h":0},{"i":8,"h":0},{"i":9,"h":0},{"i":16,"h":0},{"i":10,"h":0}],"r":False},
                {"w":4,"e":[{"i":26,"h":0}],"r":False},
                {"w":5,"e":[{"i":44,"h":0}],"r":False},
                {"w":6,"e":[{"i":11,"h":0}],"r":False},
                {"w":7,"e":[{"i":11,"h":0}],"r":False},
                {"w":8,"e":[{"i":11,"h":0}],"r":False},
                {"w":9,"e":[{"i":11,"h":0}],"r":False},
                {"w":10,"e":[{"i":44,"h":0}],"r":False},
                {"w":11,"e":[{"i":11,"h":0}],"r":False},
                {"w":12,"e":[{"i":11,"h":0}],"r":False},
                {"w":13,"e":[{"i":11,"h":0}],"r":False},
                {"w":14,"e":[{"i":11,"h":0}],"r":False},
                {"w":15,"e":[{"i":11,"h":0}],"r":False},
                {"w":16,"e":[{"i":11,"h":0}],"r":False},
                {"w":17,"e":[{"i":11,"h":0}],"r":False}
            ]
        else:
            print("输入不合法，操作取消")
            return
    
        # 将获取的注入数据更新到 p_json["sd"]["wmed"]
        if "sd" not in p_json:
            p_json["sd"] = {}
        p_json["sd"]["wmed"] = wmed_value
    
        # 重新构造JSON字符串，并进行MD5、Base64与gzip处理
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5_val = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8')\
                        .replace('+', '-').replace('/', '_').replace('=', ',')
    
        req206 = {
            "req": "V206",
            "e": {
                "m": md5_val,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
    
        encrypt_data2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=encrypt_data2.encode('utf-8'))
        if response2.status_code == 200:
            print("注入成功")
        else:
            print("注入失败")
    except Exception as e:
        print("注入失败", e)

def make_清虚存档():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        encrypt_data = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=encrypt_data.encode('utf-8'))
        if response.status_code != 200:
            print("虚存档清除注入失败")
            return
        decrypt_data = CNNetwork.decrypt(response.text)
        res = json.loads(decrypt_data)
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - (len(p_decode) % 4))
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
    
        if "sd" not in p_json:
            p_json["sd"] = {}
        p_json["sd"]["ppr"] = []
        p_json["sd"]["asp"] = []
        p_json["sd"]["psla"] = []
        p_json["sd"]["mtrl"] = []
        p_json["sd"]["lpapi"] = []
        p_json["sd"]["pasi"] = []
    
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5_val = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', ',')
    
        req206 = {
            "req": "V206",
            "e": {
                "m": md5_val,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
    
        encrypt_data2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=encrypt_data2.encode('utf-8'))
        if response2.status_code == 200:
            print("消除虚存档成功")
        else:
            print("消除虚存档失败")
    except Exception as e:
        print("消除虚存档失败", e)

def make_2倍速():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        encrypt_data = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=encrypt_data.encode('utf-8'))
        if response.status_code != 200:
            print("2倍速注入失败")
            return
        decrypt_data = CNNetwork.decrypt(response.text)
        res = json.loads(decrypt_data)
        # 获取返回数据中的用户信息
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - (len(p_decode) % 4))
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
    
        # 设置2倍速相关字段 urn
        if "sd" not in p_json:
            p_json["sd"] = {}
        urn_value = [2,20,30,40,50,60,70,80,90,100,110,120,130,140,150]
        p_json["sd"]["urn"] = urn_value
    
        # 重新构造 JSON 字符串，并进行 MD5、Base64 及 gzip 压缩处理
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5_val = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8')\
                        .replace('+', '-').replace('/', '_').replace('=', ',')
    
        req206 = {
            "req": "V206",
            "e": {
                "m": md5_val,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
    
        encrypt_data2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=encrypt_data2.encode('utf-8'))
        if response2.status_code == 200:
            print("2倍速注入成功")
        else:
            print("2倍速注入失败")
    except Exception as e:
        print("2倍速注入失败", e)

def make_穿戴全身():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        encrypt_data = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=encrypt_data.encode('utf-8'))
        if response.status_code != 200:
            print("全身装扮注入失败")
            return
        decrypt_data = CNNetwork.decrypt(response.text)
        res = json.loads(decrypt_data)
        # 获取返回数据中的用户信息
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - (len(p_decode) % 4))
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
    
        # 注入 lpaei 数据
        lpaei_value = [
            {"peapid":111029,"peaaid":31110291},
            {"peapid":111019,"peaaid":31110192},
            {"peapid":1045,"peaaid":30010451},
            {"peapid":111022,"peaaid":31110222},
            {"peapid":111016,"peaaid":31110164},
            {"peapid":111030,"peaaid":31110302},
            {"peapid":111035,"peaaid":31110354},
            {"peapid":111045,"peaaid":31110453},
            {"peapid":111067,"peaaid":31110672},
            {"peapid":111070,"peaaid":31110703},
            {"peapid":111075,"peaaid":31110753},
            {"peapid":200007,"peaaid":32000073},
            {"peapid":200021,"peaaid":32000212},
            {"peapid":200034,"peaaid":32000344},
            {"peapid":200037,"peaaid":32000372},
            {"peapid":200038,"peaaid":32000382},
            {"peapid":200051,"peaaid":32000513},
            {"peapid":200053,"peaaid":32000532},
            {"peapid":200057,"peaaid":32000572},
            {"peapid":200058,"peaaid":32000583},
            {"peapid":200060,"peaaid":32000601},
            {"peapid":200061,"peaaid":32000611},
            {"peapid":200066,"peaaid":32000662},
            {"peapid":200073,"peaaid":32000733},
            {"peapid":200079,"peaaid":32000793},
            {"peapid":200083,"peaaid":32000832},
            {"peapid":200091,"peaaid":32000912},
            {"peapid":200102,"peaaid":32001021},
            {"peapid":1008,"peaaid":30010082},
            {"peapid":1009,"peaaid":30010092},
            {"peapid":1070,"peaaid":30010703},
            {"peapid":111002,"peaaid":31110023},
            {"peapid":111014,"peaaid":31110142},
            {"peapid":111015,"peaaid":31110152},
            {"peapid":1001,"peaaid":30010013},
            {"peapid":1002,"peaaid":30010025},
            {"peapid":1003,"peaaid":30010032},
            {"peapid":1004,"peaaid":30010042},
            {"peapid":1005,"peaaid":30010053},
            {"peapid":1006,"peaaid":30010062},
            {"peapid":1007,"peaaid":30010072},
            {"peapid":1012,"peaaid":30010124},
            {"peapid":1013,"peaaid":30010131},
            {"peapid":1014,"peaaid":30010142},
            {"peapid":1016,"peaaid":30010161},
            {"peapid":1019,"peaaid":30010193},
            {"peapid":1020,"peaaid":30010201},
            {"peapid":1021,"peaaid":30010213},
            {"peapid":1023,"peaaid":30010231},
            {"peapid":1024,"peaaid":30010244},
            {"peapid":1025,"peaaid":30011251},
            {"peapid":1027,"peaaid":30010271},
            {"peapid":1029,"peaaid":30010292},
            {"peapid":1030,"peaaid":30010302},
            {"peapid":1031,"peaaid":30010313},
            {"peapid":1033,"peaaid":30010331},
            {"peapid":1037,"peaaid":30010373},
            {"peapid":1039,"peaaid":30010393},
            {"peapid":1042,"peaaid":30010421},
            {"peapid":1043,"peaaid":30010431},
            {"peapid":1044,"peaaid":30010442},
            {"peapid":1049,"peaaid":30010491},
            {"peapid":1050,"peaaid":30010502},
            {"peapid":1052,"peaaid":30010521},
            {"peapid":1055,"peaaid":30010551},
            {"peapid":1058,"peaaid":30010581},
            {"peapid":1069,"peaaid":30010691},
            {"peapid":1071,"peaaid":30010711},
            {"peapid":1072,"peaaid":30010721},
            {"peapid":1081,"peaaid":30010812},
            {"peapid":1082,"peaaid":30010821},
            {"peapid":1083,"peaaid":30010831},
            {"peapid":1086,"peaaid":30010861},
            {"peapid":1093,"peaaid":30010932},
            {"peapid":1098,"peaaid":30010981},
            {"peapid":1099,"peaaid":30010991},
            {"peapid":111001,"peaaid":31110011},
            {"peapid":111003,"peaaid":31110031},
            {"peapid":111004,"peaaid":31110041},
            {"peapid":111017,"peaaid":31110171},
            {"peapid":111023,"peaaid":31110231},
            {"peapid":111033,"peaaid":31110333},
            {"peapid":111038,"peaaid":31110381},
            {"peapid":111039,"peaaid":31110391},
            {"peapid":111040,"peaaid":31110401},
            {"peapid":111043,"peaaid":31110431},
            {"peapid":111044,"peaaid":31110441},
            {"peapid":111086,"peaaid":31110862},
            {"peapid":111021,"peaaid":31110211},
            {"peapid":111063,"peaaid":31110632},
            {"peapid":111089,"peaaid":31110893},
            {"peapid":111090,"peaaid":31110903},
            {"peapid":200001,"peaaid":32000012},
            {"peapid":200101,"peaaid":32001011},
            {"peapid":200100,"peaaid":32001002},
            {"peapid":200098,"peaaid":32000982},
            {"peapid":200095,"peaaid":32000951},
            {"peapid":200094,"peaaid":32000941},
            {"peapid":200092,"peaaid":32000921},
            {"peapid":200088,"peaaid":32000881},
            {"peapid":200074,"peaaid":32000741},
            {"peapid":200009,"peaaid":32000093},
            {"peapid":200069,"peaaid":32000692},
            {"peapid":200099,"peaaid":32000991},
            {"peapid":200127,"peaaid":32001271},
            {"peapid":200063,"peaaid":32000630},
            {"peapid":200070,"peaaid":32000700},
            {"peapid":200024,"peaaid":32000241}
        ]
        if "sd" not in p_json:
            p_json["sd"] = {}
        p_json["sd"]["lpaei"] = lpaei_value
    
        # 重新构造 JSON 字符串，并进行 MD5、Base64 与 gzip 压缩处理
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5_val = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8')\
                        .replace('+', '-').replace('/', '_').replace('=', ',')
    
        req206 = {
            "req": "V206",
            "e": {
                "m": md5_val,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
    
        encrypt_data2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=encrypt_data2.encode('utf-8'))
        if response2.status_code == 200:
            print("穿戴全身成功")
        else:
            print("穿戴全身失败")
    except Exception as e:
        print("穿戴全身失败", e)

def make_改名():
    try:
        url = 'http://cloudpvz2android.ditwan.cn/index.php'
        headers = {'Content-Type': 'multipart/form-data; boundary=_{{}}_'}
        data = {"req": "V203", "e": {"pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        encrypt_data = CNNetwork.encrypt(json.dumps(data, separators=(',', ':')))
        response = requests.post(url, headers=headers, data=encrypt_data.encode('utf-8'))
        if response.status_code != 200:
            print("改名注入失败")
            return
        decrypt_data = CNNetwork.decrypt(response.text)
        res = json.loads(decrypt_data)
        # 获取返回数据中的用户信息
        用户p = res.get("e", {}).get("d", {}).get("pr", {}).get("p", "")
        用户s = res.get("e", {}).get("d", {}).get("pr", {}).get("s", "")
        p_decode = 用户p.replace('-', '+').replace('_', '/').replace(',', '=')
        if len(p_decode) % 4:
            p_decode += '=' * (4 - (len(p_decode) % 4))
        p_json = json.loads(base64.b64decode(p_decode).decode('utf-8'))
    
        # 用户输入新名字
        new_name = input("请输入新名字：").strip()
        if not new_name:
            print("未输入新名字，操作取消")
            return
    
        # 提供10种常用颜色供选择，颜色标记格式为 ^颜色代码^名字
        colors = {
            "1": ("红色", "FF0000"),
            "2": ("蓝色", "0000FF"),
            "3": ("绿色", "00FF00"),
            "4": ("黄色", "FFFF00"),
            "5": ("橙色", "FFA500"),
            "6": ("紫色", "800080"),
            "7": ("粉色", "FFC0CB"),
            "8": ("青色", "00FFFF"),
            "9": ("白色", "FFFFFF"),
            "10": ("黑色", "000000")
        }
        print("请选择名字颜色：")
        for key, (name_cn, code) in colors.items():
            print(f"{key}. {name_cn} (^ {code} ^)")
        color_choice = input("请输入颜色编号（直接回车则使用默认颜色）：").strip()
        if color_choice in colors:
            color_code = colors[color_choice][1]
            new_name = f"^{color_code}^{new_name}"
    
        # 修改p_json中名字字段（n 必须为字符串），n位于 p_json["sd"]["n"] 下
        if "sd" not in p_json:
            p_json["sd"] = {}
        p_json["sd"]["n"] = new_name
    
        # 重新构造JSON字符串，并进行MD5、Base64和gzip压缩处理
        compact_json = json.dumps(p_json, separators=(',', ':'))
        md5_val = hashlib.md5(compact_json.encode('utf-8')).hexdigest()
        b64_1 = base64.b64encode(compact_json.encode('utf-8'))
        b64_2 = b'"' + b64_1 + b'"'
        b64_3 = b64_2.decode('utf-8').replace('=', ',')
        gzip_bytes = gzip.compress(b64_3.encode('utf-8'), compresslevel=9)
        b64_gzip = base64.b64encode(gzip_bytes).decode('utf-8').replace('+', '-').replace('/', '_').replace('=', ',')
    
        req206 = {
            "req": "V206",
            "e": {
                "m": md5_val,
                "pi": pi,
                "pr": b64_gzip,
                "s": 用户s,
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
    
        encrypt_data2 = CNNetwork.encrypt(json.dumps(req206, separators=(',', ':')))
        response2 = requests.post(url, headers=headers, data=encrypt_data2.encode('utf-8'))
        if response2.status_code == 200:
            print("改名注入成功，请重新进入游戏选择云端存档后验证新名字效果")
        else:
            print("改名注入失败")
    except Exception as e:
        print("改名注入失败", e)
#===========================僵局逃脱======================
def make_僵局逃脱():
    for i in range(1,6):
        data_僵局逃脱 = {"req":"V1030","e":{"ba":{"d":{"plantlist":[[],[]]}},"lct":"62045","li":str(0 + i),"pi":pi,"rt":"0","sk":sk,"ss":"16000,16000","ui":ui,"wi":"1"},"ev":1}
        send_加密发送_拼接提示(data_僵局逃脱,"僵局逃脱第{}关".format(i))
        
def make_僵局逃脱奖励():
    for i in range(1,16):
        data_僵局逃脱奖励 = {"req":"V1031","e":{"id":str(0 + i),"pi":pi,"sk":sk,"ui":ui,"wi":"1"},"ev":1}
        send_加密发送_拼接提示(data_僵局逃脱奖励,"僵局逃脱奖励第{}个".format(i))
#===========================儿童节秘境======================
def make_儿童节秘境普通():
    for i in range(1, 11):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "0,1,1", "type": "3", "ui": ui, "win": "1",
                      "world": "uncharted_childrensday_2025"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过儿童节秘境普通第{}关".format(i))
def make_儿童节秘境困难():
    for i in range(1, 11):
        data = {"req": "V411",
                "e": {"level": str(i - 1), "pi": pi, "sk": sk, "tgt": "13", "type": "4", "ui": ui, "win": "1",
                      "world": "uncharted_childrensday_2025"}, "ev": 1}
        send_加密发送_拼接提示(data, "通过儿童节秘境困难第{}关".format(i))
def make_儿童节秘境奖励():
    for i in range(50):
     index_value = 1001 + i
     levelid_value = 0 + (i // 5)
     data = {"req": "V415", "e": {"index": index_value, "levelid": levelid_value, "pi": pi, "sk": sk, "ui": ui, "world": "uncharted_childrensday_2025"}, "ev": 1}
     send_加密发送_拼接提示(data, "领取儿童节秘境奖励第{}个".format(i + 1))
def make_超z买钥匙():
    global uk
    make_ukugd()
    for i in range(1):
        超z买钥匙 = {'req': 'V209', 'e': {"is": "0","oi": "52282", "pi": pi, "q": "30", "si": "15", "sk": sk, "ui": ui, "uk": str(int(uk) + 1)}, "ev": 1}
        send_加密发送_拼接提示(超z买钥匙,"钥匙购买".format(i))

def make_世界关卡装扮():
    global uk
    make_ukugd()
    data = {"req":"V302","e":{"nfc":"1","o":[{"i":1355,"q":2,"f":"safe18_hard_level_reward"},{"i":1355,"q":2,"f":"safe18_hard_level_reward"},{"i":1355,"q":3,"f":"safe18_hard_level_reward"},{"i":1355,"q":3,"f":"safe18_hard_level_reward"},{"i":1355,"q":3,"f":"safe18_hard_level_reward"},{"i":1356,"q":2,"f":"safe18_hard_level_reward"},{"i":1356,"q":2,"f":"safe18_hard_level_reward"},{"i":1356,"q":2,"f":"safe18_hard_level_reward"},{"i":1356,"q":2,"f":"safe18_hard_level_reward"},{"i":1356,"q":2,"f":"safe18_hard_level_reward"},{"i":1310,"q":2,"f":"safe18_hard_level_reward"},{"i":1310,"q":2,"f":"safe18_hard_level_reward"},{"i":1310,"q":3,"f":"safe18_hard_level_reward"},{"i":1310,"q":3,"f":"safe18_hard_level_reward"},{"i":1310,"q":3,"f":"safe18_hard_level_reward"},{"i":1311,"q":2,"f":"safe18_hard_level_reward"},{"i":1311,"q":2,"f":"safe18_hard_level_reward"},{"i":1311,"q":3,"f":"safe18_hard_level_reward"},{"i":1311,"q":3,"f":"safe18_hard_level_reward"},{"i":1311,"q":3,"f":"safe18_hard_level_reward"},{"i":1321,"q":2,"f":"safe18_hard_level_reward"},{"i":1321,"q":2,"f":"safe18_hard_level_reward"},{"i":1321,"q":2,"f":"safe18_hard_level_reward"},{"i":1321,"q":2,"f":"safe18_hard_level_reward"},{"i":1321,"q":2,"f":"safe18_hard_level_reward"},{"i":1315,"q":2,"f":"safe18_hard_level_reward"},{"i":1315,"q":2,"f":"safe18_hard_level_reward"},{"i":1315,"q":3,"f":"safe18_hard_level_reward"},{"i":1315,"q":3,"f":"safe18_hard_level_reward"},{"i":1315,"q":3,"f":"safe18_hard_level_reward"},{"i":1316,"q":3,"f":"safe18_hard_level_reward"},{"i":1316,"q":3,"f":"safe18_hard_level_reward"},{"i":1316,"q":4,"f":"safe18_hard_level_reward"},{"i":1316,"q":4,"f":"safe18_hard_level_reward"},{"i":1316,"q":4,"f":"safe18_hard_level_reward"},{"i":1322,"q":2,"f":"safe18_hard_level_reward"},{"i":1322,"q":2,"f":"safe18_hard_level_reward"},{"i":1322,"q":2,"f":"safe18_hard_level_reward"},{"i":1322,"q":2,"f":"safe18_hard_level_reward"},{"i":1322,"q":2,"f":"safe18_hard_level_reward"},{"i":1302,"q":1,"f":"safe18_hard_level_reward"},{"i":1302,"q":1,"f":"safe18_hard_level_reward"},{"i":1302,"q":1,"f":"safe18_hard_level_reward"},{"i":1302,"q":1,"f":"safe18_hard_level_reward"},{"i":1302,"q":2,"f":"safe18_hard_level_reward"},{"i":1303,"q":1,"f":"safe18_hard_level_reward"},{"i":1303,"q":1,"f":"safe18_hard_level_reward"},{"i":1303,"q":1,"f":"safe18_hard_level_reward"},{"i":1303,"q":1,"f":"safe18_hard_level_reward"},{"i":1303,"q":2,"f":"safe18_hard_level_reward"},{"i":1304,"q":2,"f":"safe18_hard_level_reward"},{"i":1304,"q":2,"f":"safe18_hard_level_reward"},{"i":1304,"q":2,"f":"safe18_hard_level_reward"},{"i":1304,"q":2,"f":"safe18_hard_level_reward"},{"i":1304,"q":2,"f":"safe18_hard_level_reward"},{"i":1301,"q":2,"f":"safe18_hard_level_reward"},{"i":1301,"q":2,"f":"safe18_hard_level_reward"},{"i":1301,"q":3,"f":"safe18_hard_level_reward"},{"i":1301,"q":3,"f":"safe18_hard_level_reward"},{"i":1301,"q":3,"f":"safe18_hard_level_reward"},{"i":1334,"q":2,"f":"safe18_hard_level_reward"},{"i":1334,"q":2,"f":"safe18_hard_level_reward"},{"i":1334,"q":3,"f":"safe18_hard_level_reward"},{"i":1334,"q":3,"f":"safe18_hard_level_reward"},{"i":1334,"q":3,"f":"safe18_hard_level_reward"},{"i":1335,"q":2,"f":"safe18_hard_level_reward"},{"i":1335,"q":2,"f":"safe18_hard_level_reward"},{"i":1335,"q":2,"f":"safe18_hard_level_reward"},{"i":1335,"q":2,"f":"safe18_hard_level_reward"},{"i":1335,"q":2,"f":"safe18_hard_level_reward"},{"i":1350,"q":3,"f":"safe18_hard_level_reward"},{"i":1350,"q":3,"f":"safe18_hard_level_reward"},{"i":1350,"q":4,"f":"safe18_hard_level_reward"},{"i":1350,"q":4,"f":"safe18_hard_level_reward"},{"i":1350,"q":4,"f":"safe18_hard_level_reward"},{"i":1305,"q":1,"f":"safe18_hard_level_reward"},{"i":1305,"q":1,"f":"safe18_hard_level_reward"},{"i":1305,"q":1,"f":"safe18_hard_level_reward"},{"i":1305,"q":1,"f":"safe18_hard_level_reward"},{"i":1305,"q":2,"f":"safe18_hard_level_reward"},{"i":1364,"q":6,"f":"safe18_hard_level_reward"},{"i":1364,"q":6,"f":"safe18_hard_level_reward"},{"i":1364,"q":6,"f":"safe18_hard_level_reward"},{"i":1364,"q":6,"f":"safe18_hard_level_reward"},{"i":1364,"q":6,"f":"safe18_hard_level_reward"},{"i":1366,"q":2,"f":"safe18_hard_level_reward"},{"i":1366,"q":2,"f":"safe18_hard_level_reward"},{"i":1366,"q":2,"f":"safe18_hard_level_reward"},{"i":1366,"q":2,"f":"safe18_hard_level_reward"},{"i":1366,"q":2,"f":"safe18_hard_level_reward"},{"i":1306,"q":2,"f":"safe18_hard_level_reward"},{"i":1306,"q":2,"f":"safe18_hard_level_reward"},{"i":1306,"q":3,"f":"safe18_hard_level_reward"},{"i":1306,"q":3,"f":"safe18_hard_level_reward"},{"i":1306,"q":3,"f":"safe18_hard_level_reward"},{"i":1378,"q":6,"f":"safe18_hard_level_reward"},{"i":1378,"q":6,"f":"safe18_hard_level_reward"},{"i":1378,"q":6,"f":"safe18_hard_level_reward"},{"i":1378,"q":6,"f":"safe18_hard_level_reward"},{"i":1378,"q":6,"f":"safe18_hard_level_reward"},{"i":1383,"q":2,"f":"safe18_hard_level_reward"},{"i":1383,"q":2,"f":"safe18_hard_level_reward"},{"i":1383,"q":2,"f":"safe18_hard_level_reward"},{"i":1383,"q":2,"f":"safe18_hard_level_reward"},{"i":1383,"q":2,"f":"safe18_hard_level_reward"},{"i":1389,"q":6,"f":"safe18_hard_level_reward"},{"i":1389,"q":6,"f":"safe18_hard_level_reward"},{"i":1389,"q":6,"f":"safe18_hard_level_reward"},{"i":1389,"q":6,"f":"safe18_hard_level_reward"},{"i":1389,"q":6,"f":"safe18_hard_level_reward"},{"i":1390,"q":6,"f":"safe18_hard_level_reward"},{"i":1390,"q":6,"f":"safe18_hard_level_reward"},{"i":1390,"q":6,"f":"safe18_hard_level_reward"},{"i":1390,"q":6,"f":"safe18_hard_level_reward"},{"i":1390,"q":6,"f":"safe18_hard_level_reward"},{"i":1394,"q":2,"f":"safe18_hard_level_reward"},{"i":1394,"q":2,"f":"safe18_hard_level_reward"},{"i":1394,"q":2,"f":"safe18_hard_level_reward"},{"i":1394,"q":2,"f":"safe18_hard_level_reward"},{"i":1394,"q":2,"f":"safe18_hard_level_reward"},{"i":111309,"q":6,"f":"safe18_hard_level_reward"},{"i":111309,"q":6,"f":"safe18_hard_level_reward"},{"i":111309,"q":6,"f":"safe18_hard_level_reward"},{"i":111309,"q":6,"f":"safe18_hard_level_reward"},{"i":111309,"q":6,"f":"safe18_hard_level_reward"},{"i":111308,"q":6,"f":"safe18_hard_level_reward"},{"i":111308,"q":6,"f":"safe18_hard_level_reward"},{"i":111308,"q":6,"f":"safe18_hard_level_reward"},{"i":111308,"q":6,"f":"safe18_hard_level_reward"},{"i":111308,"q":6,"f":"safe18_hard_level_reward"},{"i":1392,"q":2,"f":"safe18_hard_level_reward"},{"i":1392,"q":2,"f":"safe18_hard_level_reward"},{"i":1392,"q":2,"f":"safe18_hard_level_reward"},{"i":1392,"q":2,"f":"safe18_hard_level_reward"},{"i":1392,"q":2,"f":"safe18_hard_level_reward"},{"i":111327,"q":6,"f":"safe18_hard_level_reward"},{"i":111327,"q":6,"f":"safe18_hard_level_reward"},{"i":111327,"q":6,"f":"safe18_hard_level_reward"},{"i":111327,"q":6,"f":"safe18_hard_level_reward"},{"i":111327,"q":6,"f":"safe18_hard_level_reward"},{"i":111325,"q":6,"f":"safe18_hard_level_reward"},{"i":111325,"q":6,"f":"safe18_hard_level_reward"},{"i":111325,"q":6,"f":"safe18_hard_level_reward"},{"i":111325,"q":6,"f":"safe18_hard_level_reward"},{"i":111325,"q":6,"f":"safe18_hard_level_reward"},{"i":111326,"q":6,"f":"safe18_hard_level_reward"},{"i":111326,"q":6,"f":"safe18_hard_level_reward"},{"i":111326,"q":6,"f":"safe18_hard_level_reward"},{"i":111326,"q":6,"f":"safe18_hard_level_reward"},{"i":111326,"q":6,"f":"safe18_hard_level_reward"},{"i":111335,"q":6,"f":"safe18_hard_level_reward"},{"i":111335,"q":6,"f":"safe18_hard_level_reward"},{"i":111335,"q":6,"f":"safe18_hard_level_reward"},{"i":111335,"q":6,"f":"safe18_hard_level_reward"},{"i":111335,"q":6,"f":"safe18_hard_level_reward"},{"i":111336,"q":6,"f":"safe18_hard_level_reward"},{"i":111336,"q":6,"f":"safe18_hard_level_reward"},{"i":111336,"q":6,"f":"safe18_hard_level_reward"},{"i":111336,"q":6,"f":"safe18_hard_level_reward"},{"i":111336,"q":6,"f":"safe18_hard_level_reward"},{"i":111338,"q":6,"f":"safe18_hard_level_reward"},{"i":111338,"q":6,"f":"safe18_hard_level_reward"},{"i":111338,"q":6,"f":"safe18_hard_level_reward"},{"i":111338,"q":6,"f":"safe18_hard_level_reward"},{"i":111338,"q":6,"f":"safe18_hard_level_reward"},{"i":111351,"q":6,"f":"safe18_hard_level_reward"},{"i":111351,"q":6,"f":"safe18_hard_level_reward"},{"i":111351,"q":6,"f":"safe18_hard_level_reward"},{"i":111351,"q":6,"f":"safe18_hard_level_reward"},{"i":111351,"q":6,"f":"safe18_hard_level_reward"},{"i":111352,"q":6,"f":"safe18_hard_level_reward"},{"i":111352,"q":6,"f":"safe18_hard_level_reward"},{"i":111352,"q":6,"f":"safe18_hard_level_reward"},{"i":111352,"q":6,"f":"safe18_hard_level_reward"},{"i":111352,"q":6,"f":"safe18_hard_level_reward"},{"i":111356,"q":6,"f":"safe18_hard_level_reward"},{"i":111356,"q":6,"f":"safe18_hard_level_reward"},{"i":111356,"q":6,"f":"safe18_hard_level_reward"},{"i":111356,"q":6,"f":"safe18_hard_level_reward"},{"i":111356,"q":6,"f":"safe18_hard_level_reward"},{"i":111366,"q":6,"f":"safe18_hard_level_reward"},{"i":111366,"q":6,"f":"safe18_hard_level_reward"},{"i":111366,"q":6,"f":"safe18_hard_level_reward"},{"i":111366,"q":6,"f":"safe18_hard_level_reward"},{"i":111366,"q":6,"f":"safe18_hard_level_reward"},{"i":111368,"q":6,"f":"safe18_hard_level_reward"},{"i":111368,"q":6,"f":"safe18_hard_level_reward"},{"i":111368,"q":6,"f":"safe18_hard_level_reward"},{"i":111368,"q":6,"f":"safe18_hard_level_reward"},{"i":111368,"q":6,"f":"safe18_hard_level_reward"},{"i":111369,"q":6,"f":"safe18_hard_level_reward"},{"i":111369,"q":6,"f":"safe18_hard_level_reward"},{"i":111369,"q":6,"f":"safe18_hard_level_reward"},{"i":111369,"q":6,"f":"safe18_hard_level_reward"},{"i":111369,"q":6,"f":"safe18_hard_level_reward"},{"i":111391,"q":6,"f":"safe18_hard_level_reward"},{"i":111391,"q":6,"f":"safe18_hard_level_reward"},{"i":111391,"q":6,"f":"safe18_hard_level_reward"},{"i":111391,"q":6,"f":"safe18_hard_level_reward"},{"i":111391,"q":6,"f":"safe18_hard_level_reward"},{"i":111389,"q":6,"f":"safe18_hard_level_reward"},{"i":111389,"q":6,"f":"safe18_hard_level_reward"},{"i":111389,"q":6,"f":"safe18_hard_level_reward"},{"i":111389,"q":6,"f":"safe18_hard_level_reward"},{"i":111389,"q":6,"f":"safe18_hard_level_reward"},{"i":1398,"q":6,"f":"safe18_hard_level_reward"},{"i":1398,"q":6,"f":"safe18_hard_level_reward"},{"i":1398,"q":6,"f":"safe18_hard_level_reward"},{"i":1398,"q":6,"f":"safe18_hard_level_reward"},{"i":1398,"q":6,"f":"safe18_hard_level_reward"}],"pi":pi,"sk":sk,"ui":ui,"uk":str(int(uk)+1)},"ev":1}
    send_加密发送_拼接提示(data, "世界关卡装扮获取")

def make_世界植物():
    世界植物 = [1064, 111041, 200016, 200017, 200018, 200003, 111091, 111089, 111069, 111066, 111065, 111056, 111052, 111035, 111037, 111025, 111028, 111014, 111009, 111006, 1094, 1090, 1089, 1083, 1079, 1078, 1068, 1066, 1057, 1055, 1052, 1050, 1042, 1041, 1035, 1034, 1022, 1016, 1015, 1011, 1010, 1021, 1018, 1006, 1005]
    for i_value in 世界植物:
        plant_name = 植物字典.get(str(i_value), f"未知({i_value})")
        data = {
            "req": "V900",
            "e": {"pi": pi, "pl": [{"i": i_value, "q": 1}], "sk": sk, "ui": ui},
            "ev": 1
        }
        send_加密发送_拼接提示(data, "世界植物获取{}".format(plant_name))
def make_双人段位奖励():
    for i in range(25):
        data ={"req": "V831", "e": {"index": 4+i+1, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
        send_加密发送_拼接提示(data, "双人段位奖励第{}个".format(i+1))

def make_僵尸升级():
    result = make_查双人僵尸()
    if result is None:
        print("无法获取僵尸信息，升级中断")
        return
    activated_info, fragments_dict = result
    combined = {}
    for zombie in activated_info:
        base_id = zombie.get("base_id")
        if base_id is None:
            continue
        combined[base_id] = zombie
    for chip_code_str, qty in fragments_dict.items():
        try:
            chip_code = int(chip_code_str)
            candidate_base = chip_code - 4000
        except Exception:
            continue
        if candidate_base not in combined:
            name = 双人对决僵尸字典.get(chip_code_str, str(candidate_base))
            combined[candidate_base] = {"name": name, "lv": 0, "base_id": candidate_base}
    if not combined:
        print("无僵尸可升级")
        return
    cost_table = {0: 1, 1: 5, 2: 10, 3: 20, 4: 40, 5: 100, 6: 200, 7: 300, 8: 400, 9: 800}
    upgrade_occurred = False 
    for base_id, zombie in combined.items():
        current_level = zombie.get("lv", 0)
        fragment_key = str(base_id + 4000)
        available = int(fragments_dict.get(fragment_key, 0))
        while current_level < 10:
            required = cost_table.get(current_level, 0)
            if available < required:
                break
            data = {
                "req": "V832",
                "e": {"id": base_id, "pi": pi, "sk": sk, "ui": ui},
                "ev": 1
            }
            send_加密发送_拼接提示(
                data,
                f"僵尸升级 {zombie['name']} 从 {current_level}级到 {current_level+1}级 (需 {required}，当前 {available}) 成功"
            )
            available -= required
            current_level += 1
            upgrade_occurred = True
    if not upgrade_occurred:
        print("无僵尸可升级")
def make_基因抽取():
    try:
        抽取次数 = int(input("请输入基因抽取次数："))
    except ValueError:
        print("无效输入")
        return
    for i in range(抽取次数):
        data_基因抽取 = {"req":"V851","e":{"pi":pi,"sk":sk,"t":"1","ui":ui},"ev":1}
        send_加密发送_拼接提示(data_基因抽取, f"基因抽取第{i+1}十次")

def make_基因升级():
    data_V316 = {
        "req": "V316",
        "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui},
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data_V316)
    try:
        genecl = decrypted_json['genecl']
    except Exception as e:
        print("无法提取基因数据，完整解密响应如下：")
        print(decrypted_json)
        return
    try:
        result = [d for d in genecl if isinstance(d["q"], (int, float)) and d["q"] > 0]
        for item in result:
            if isinstance(item["i"], int):
                item["i"] = item["i"] - 10000
            elif isinstance(item["i"], str) and item["i"].isdigit():
                item["i"] = int(item["i"]) - 10000
        for item in result:
            gi = item["i"]
            for _ in range(int(item["q"])):
                data = {
                    "req": "V850",
                    "e": {"gi": gi, "pi": pi, "sk": sk, "ui": ui},
                    "ev": 1
                }
                send_加密发送_拼接提示(data, f"基因升级 gi={gi}")
    except Exception as e:
        print("在处理基因升级数据时出错，完整解密响应如下：")
        print(decrypted_json)

def make_0分僵博():
    data =  {"req":"V303","e":{"al":[{"id":10800,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":渠道,"pi":pi,"sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(data, "进入追击")
    for i in range(4):
           data_刷能量 = {"req": "V927", "e": {"fr": {"t": "1", "l": "5", "g": "3", "s": "0", "r": "1", "b": "1.000000"}, "g": "1", "on": "02f80dedd5ca4450801d951ceaee65e7", "pi": pi, "pr": {"pl": [{"i": 1003, "q": 4}, {"i": 1030, "q": 4}, {"i": 111029, "q": 2}, {"i": 1040, "q": 4}, {"i": 1002, "q": 4}, {"i": 1024, "q": 4}, {"i": 1001, "q": 4}]}, "sk": sk, "ui": ui}, "ev": 1}
           send_加密发送_拼接提示(data_刷能量, "刷能量{}次".format(i+1))
    for i in range(3):
           data = {"req": "V927", "e": {"fr": {"t": "2", "l": 0+i+1, "g": 0+i+1, "s": "0", "r": "1", "b": "2.000000"}, "g": "1", "on": "", "pi": pi, "pr": {"pl": [{"i": 1052, "q": 1}, {"i": 111040, "q": 4}, {"i": 111038, "q": 5}, {"i": 111019, "q": 2}, {"i": 1030, "q": 5}, {"i": 1022, "q": 4}, {"i": 111035, "q": 5}]}, "sk":sk, "ui": ui}, "ev": 1}
           send_加密发送_拼接提示(data, "刷僵博{}次".format(i+1))

def make_双人胜败查询():
    data = {"req": "V303", "e": {"al": [{"id": 10859, "abi": 0, "type": 1, "config_version": 1}], "ci": "93", "cs": "0", "pack": 渠道, "pi":pi, "sk": sk, "ui":ui, "v": newest_version}, "ev": 1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        data_str = decrypted_json[0]['data']
        data_dict = json.loads(data_str)
        pf_data = data_dict['pf']
    except Exception as e:
        print("未能提取到所需数据，完整解密响应如下：")
        print(decrypted_json)
        return
    try:
        grade = pf_data['grade']
        big = grade['big']
        small = grade['small']
        star = grade['star']
        big_rank_mapping = {0: "铜锅", 1: "银锅", 2: "金锅", 3: "钻锅", 4: "大师锅", 5: "宗师锅"}
        small_rank_mapping = {0: "V", 1: "IV", 2: "III", 3: "II", 4: "I"}
        big_rank = big_rank_mapping.get(big, f"未知大等级({big})")
        small_rank = small_rank_mapping.get(small, f"未知小等级({small})")
        print(f"当前段位：{big_rank}{small_rank}  {star}星")
        print("与玩家对战数:", pf_data.get("fight_count", 0))
        print("总胜场:", pf_data.get("win_count", 0))
        print("满血胜利数:", pf_data.get("full_hp_win_count", 0))
        print("总败场:", pf_data.get("lost_count", 0))
        print("最高连胜数:", pf_data.get("con_win_max", 0))
        print("目前连胜数:", pf_data.get("con_win_count", 0))
        print("最高评分:", pf_data.get("rating_max", 0))
        print("种植植物总数:", pf_data.get("plat_plants", 0))
        print("击杀僵尸总数:", pf_data.get("kill_zombies", 0))
        print("释放僵尸总数:", pf_data.get("release_zombies", 0))
        fight_count = pf_data.get("fight_count", 0)
        lost_count = pf_data.get("lost_count", 0)
        if fight_count:
            win_rate = (fight_count - lost_count) / fight_count * 100
            print(f"对人胜率: {win_rate:.2f}%")
        else:
            print("对人胜率: 无数据")
    except Exception as e:
        print("解析部分对战数据时出错，完整解密响应如下：")
        print(decrypted_json)

def make_植物激活():
    data_V316 = {
        "req": "V316",
        "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui},
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data_V316)    
    try:
        pcl_values = decrypted_json['pcl']
        pl_value = decrypted_json['pl']
    except Exception as e:
        print("无法提取植物数据，完整解密响应如下：")
        print(decrypted_json)
        return
    try:
        oi_value = []
        a_value = []
        for item in pl_value:
            i = item.get("i")
            if isinstance(i, str) and i.isdigit():
                i = int(i)
            elif isinstance(i, int):
                i = i
            else:
                continue
            a_value.append(i)
        new_a_value = []
        for num in a_value:
            if num < 2000:
                new_num = num + 100
            elif 100000 < num < 190000:
                new_num = num + 100
            elif 199999 < num < 1000000:
                new_num = num * 10 + 20000000
            else:
                new_num = num
            new_a_value.append(new_num)
        for item in pcl_values:
            q = item.get("q")
            if isinstance(q, str) and q.isdigit():
                q_value = int(q)
            else:
                q_value = q
            if q_value is not None and q_value >= 30:
                oi = item.get("i")
                if isinstance(oi, str) and oi.isdigit():
                    oi_value.append(int(oi))
                elif isinstance(oi, int):
                    oi_value.append(oi)
        result = [num for num in oi_value if num not in new_a_value]
        
        for oi in result:
            data = {"req": "V229",
                    "e": {"oi": oi, "pi": pi, "sk": sk, "ui": ui},
                    "ev": 1}
            mapped_name = 植物字典.get(str(oi))
            output = mapped_name if mapped_name is not None else str(oi)
            send_加密发送_拼接提示(data, f"植物激活 {output}")
    except Exception as e:
        print("在解析植物激活数据时出错，完整解密响应如下：")
        print(decrypted_json)

def make_植物升阶():
    stage_names = ["2阶", "3阶", "4阶", "5阶"]
    for i in range(4):
        data_V316 = {
            "req": "V316",
            "e": {"b": "0", "n": "1", "pi": pi, "sk": sk, "ui": ui},
            "ev": 1
        }
        _, decrypted_json = send_加密发送_解密响应(data_V316)
        
        try:
            pl_values = decrypted_json['pl']
            value_lists = [[], [], [], []]
            conditions = [(0, 0), (1, 1), (2, 2), (3, 3)]
            for item in pl_values:
                s = item.get("s")
                s = int(s) if isinstance(s, str) else s
                for idx, (cond1, cond2) in enumerate(conditions):
                    if s == cond1 or s == cond2:
                        value_lists[idx].append(int(item["i"]))
            new_value_lists = []
            for num_list in value_lists:
                new_list = []
                for num in num_list:
                    if num < 2000:
                        new_num = num + 100
                    elif 100000 < num < 190000:
                        new_num = num + 100
                    elif 199999 < num < 1000000:
                        new_num = num * 10 + 20000000
                    else:
                        new_num = num
                    new_list.append(new_num)
                new_value_lists.append(new_list)
            new_i_value, new_ii_value, new_iii_value, new_iv_value = new_value_lists
            pcl_values = decrypted_json['pcl']
            th_value = []
            fo_value = []
            foi_value = []
            fi_value = []
            for item in pcl_values:
                q_raw = item.get("q")
                if isinstance(q_raw, str) and q_raw.isdigit():
                    q_value = int(q_raw)
                else:
                    q_value = q_raw
                if q_value is None:
                    continue
                if q_value >= 30:
                    th_value.append(int(item["i"]))
                if q_value >= 50:
                    fo_value.append(int(item["i"]))
                if q_value >= 50:
                    foi_value.append(int(item["i"]))
                if q_value >= 80:
                    fi_value.append(int(item["i"]))
            nums_to_remove = [111145, 111147, 111133, 111123, 22000340, 22000510, 22000580, 22000600, 22000700, 111170, 22000830]
            th_value = [num for num in th_value if num not in nums_to_remove]
            fo_value = [num for num in fo_value if num not in nums_to_remove]
            foi_value = [num for num in foi_value if num not in nums_to_remove]
            fi_value = [num for num in fi_value if num not in nums_to_remove]
            th_value = [num for num in th_value if num in new_i_value]
            fo_value = [num for num in fo_value if num in new_ii_value]
            foi_value = [num for num in foi_value if num in new_iii_value]
            fi_value = [num for num in fi_value if num in new_iv_value]
            groups = [th_value, fo_value, foi_value, fi_value]
            current_group = groups[i]
            for oi in current_group:
                data = {
                    "req": "V231",
                    "e": {"oi": oi, "pi": pi, "sk": sk, "ui": ui},
                    "ev": 1
                }
                mapped_name = 植物字典.get(str(oi))
                output = mapped_name if mapped_name is not None else str(oi)
                send_加密发送_拼接提示(data, f"植物升阶 {stage_names[i]} 成功: {output}")
        except Exception as e:
            print("在解析植物升阶数据时出错，完整解密响应如下：")
            print(decrypted_json)

def make_植物装扮激活():
    data_V316 = {
        "req": "V316",
        "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui},
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data_V316)

    try:
        dcl = decrypted_json['dcl']
        ndcl = decrypted_json['ndcl']
    except Exception as e:
        print("无法提取 dcl/ndcl 数据，完整响应如下：")
        print(decrypted_json)
        return
    gl_data = []
    try:
        di_value = []
        for item in dcl:
            item['q'] = int(item['q'])
            if item['q'] >= 30:
                i_value = item['i']
                if isinstance(i_value, int) or (isinstance(i_value, str) and i_value.isdigit()):
                    num = int(i_value)
                    if num < 100000:
                        num -= 100
                    elif 100000 <= num < 10000000:
                        num -= 100
                    elif num >= 10000000:
                        num -= 10000000
                    di_value.append(num)
        for di_num in di_value:
            data = {"req": "V797", "e": {"di": di_num, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
            mapped_name = 植物装扮字典.get(str(di_num))
            output = mapped_name if mapped_name is not None else str(di_num)
            send_加密发送_拼接提示(data, f"装扮激活成功, {output}")
            
        ndi_value = []
        for item in ndcl:
            item['q'] = int(item['q'])
            if item['q'] >= 30:
                i_value = item['i']
                if isinstance(i_value, int) or (isinstance(i_value, str) and i_value.isdigit()):
                    num = int(i_value)
                    if num < 100000:
                        num -= 100
                    elif 100000 <= num < 10000000:
                        num -= 100
                    elif num >= 10000000:
                        num -= 10000000
                    ndi_value.append(num)
        for ndi_num in ndi_value:
            data = {"req": "V797", "e": {"di": ndi_num, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
            _, decrypted_json = send_加密发送_解密响应(data)
        gl_data = decrypted_json.get("gl", [])
        if not gl_data:
            print("当前无可激活装扮")
    except Exception as e:
        print("在解析装扮激活数据时出错，完整响应如下：")
        print(decrypted_json)
        if 'gl_data' not in locals():
            gl_data = []
        wei_value = [item for item in dcl if int(item['q']) < 30]
        for item_gl in gl_data:
            gl_i = item_gl.get("i")
            gl_q = item_gl.get("q", 0)
            for item_wei in wei_value:
                try:
                    if int(item_wei["i"]) == int(gl_i):
                        item_wei["q"] = int(item_wei.get("q", 0)) + int(gl_q)
                except:
                    pass
        for item in wei_value:
            if int(item["q"]) == 30:
                i_val = int(item["i"])
                if i_val < 100000:
                    i_val -= 100
                elif i_val < 10000000:
                    i_val -= 100
                else:
                    i_val -= 10000000
                data = {"req": "V797", "e": {"di": i_val, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
                mapped_name = 植物装扮字典.get(str(i_val))
                output = mapped_name if mapped_name is not None else str(i_val)
                send_加密发送_拼接提示(data, f"装扮激活成功, {output}")

def make_植物装扮转基因():
    data_V316 = {
        "req": "V316",
        "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui},
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data_V316)
    
    try:
        dl   = decrypted_json['dl']
        ndl  = decrypted_json['ndl']
        dcl  = decrypted_json['dcl']
        ndcl = decrypted_json['ndcl']
    except Exception as e:
        print("无法提取 dl/ndl 数据，完整响应如下：")
        print(decrypted_json)
        return
    try:
        total_reward = 0 
        reward_summary = {}

        new_dl = []
        for num in dl:
            if num < 100000:
                new_num = num + 100
            elif num < 10000000:
                new_num = num + 100
            else:
                new_num = num + 10000000
            new_dl.append({"i": new_num, "q": "30"})
        json_str = json.loads(json.dumps(new_dl, separators=(',', ':')))
        for item in dcl:
            item['i'] = int(item['i'])
        for item_dcl in dcl:
            for item_json in json_str:
                if int(item_dcl['i']) == int(item_json['i']):
                    item_dcl['q'] = int(item_dcl['q']) + int(item_json['q'])
        for item_json in json_str:
            i_value = int(item_json['i'])
            flag = True
            for item_dcl in dcl:
                if int(item_dcl['i']) == i_value:
                    flag = False
                    break
            if flag:
                dcl.append({'i': i_value, 'q': item_json['q']})
        for item in dcl:
            item['q'] = int(item['q'])
        wei_value = [item for item in dcl if item['q'] < 30]
        dcl = [item for item in dcl if item['q'] >= 30]
        for item in dcl:
            item['q'] = int(item['q'])
            if item['q'] >= 30:
                item['q'] = (item['q'] - 30) // 3
        dcl = json.loads(json.dumps(dcl, separators=(',', ':')))
        for item in dcl:
            i_value = item['i']
            q_value = item['q']
            for _ in range(q_value):
                data = {"req": "V907",
                        "e": {"ad": "0", "l": [i_value, i_value, i_value],
                              "pi": pi, "sk": sk, "t": "1", "ui": ui},
                        "ev": 1}
                _, decrypted_resp = send_加密发送_解密响应(data)
                if isinstance(decrypted_resp, dict) and "gl" in decrypted_resp:
                    for resp_item in decrypted_resp["gl"]:
                        frag_code = resp_item.get("i")
                        qty = resp_item.get("q")
                        mapped_name = 植物装扮碎片字典.get(str(frag_code))
                        output = mapped_name if mapped_name is not None else str(frag_code)
                        print(f"获得: {output} 数量: {qty}")
                        total_reward += int(qty)
                        reward_summary[output] = reward_summary.get(output, 0) + int(qty)
                else:
                    print("响应解析错误：找不到 gl 字段")
                    print("完整响应：", decrypted_resp)
        new_ndl = []
        for num in ndl:
            if num < 100000:
                new_num = num + 100
            elif num < 10000000:
                new_num = num + 100
            else:
                new_num = num + 10000000
            new_ndl.append({"i": new_num, "q": "30"})
        json_str = json.loads(json.dumps(new_ndl, separators=(',', ':')))
        for item in ndcl:
            item['i'] = int(item['i'])
        for item_ndcl in ndcl:
            for item_json in json_str:
                if int(item_ndcl['i']) == int(item_json['i']):
                    item_ndcl['q'] = int(item_ndcl['q']) + int(item_json['q'])
        for item_json in json_str:
            i_value = int(item_json['i'])
            flag = True
            for item_ndcl in ndcl:
                if int(item_ndcl['i']) == i_value:
                    flag = False
                    break
            if flag:
                ndcl.append({'i': i_value, 'q': item_json['q']})
        for item in ndcl:
            item['q'] = int(item['q'])
        wei_value = [item for item in ndcl if item['q'] < 30]
        ndcl = [item for item in ndcl if item['q'] >= 30]
        for item in ndcl:
            item['q'] = int(item['q'])
            if item['q'] >= 30:
                item['q'] = (item['q'] - 30) // 3
        ndcl = json.loads(json.dumps(ndcl, separators=(',', ':')))
        for item in ndcl:
            i_value = item['i']
            q_value = item['q']
            for _ in range(q_value):
                data = {"req": "V907",
                        "e": {"ad": "0", "l": [i_value, i_value, i_value],
                              "pi": pi, "sk": sk, "t": "1", "ui": ui},
                        "ev": 1}
                _, decrypted_resp = send_加密发送_解密响应(data)
                if isinstance(decrypted_resp, dict) and "gl" in decrypted_resp:
                    for resp_item in decrypted_resp["gl"]:
                        frag_code = resp_item.get("i")
                        qty = resp_item.get("q")
                        mapped_name = 植物装扮碎片字典.get(str(frag_code))
                        output = mapped_name if mapped_name is not None else str(frag_code)
                        print(f"获得: {output} 数量: {qty}")
                        total_reward += int(qty)
                        reward_summary[output] = reward_summary.get(output, 0) + int(qty)
                else:
                    print("响应解析错误：找不到 gl 字段")
                    print("完整响应：", decrypted_resp)
        print("奖励统计明细：")
        for reward, count in reward_summary.items():
            print(f"  {reward}: {count}个")
        print(f"总奖励数: {total_reward}个")
    except Exception as e:
        print("在解析装扮转基因数据时出错，完整响应如下：")
        print(decrypted_json)
def make_自动转基因():
    import math
    def get_frag_code(plant_code):
        if plant_code < 2000:
            return plant_code + 100
        elif 100000 < plant_code < 190000:
            return plant_code + 100
        elif 199999 < plant_code < 1000000:
            return plant_code * 10 + 20000000
        else:
            return plant_code

    data_V316 = {
        "req": "V316",
        "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui},
        "ev": 1
    }
    _, decrypted_json1 = send_加密发送_解密响应(data_V316)
    try:
        pcl_values = decrypted_json1['pcl']   
        pl_values  = decrypted_json1['pl']      
    except Exception as e:
        print("无法提取植物碎片数据，完整响应如下：")
        print(decrypted_json1)
        return
    pcl_map = {}
    for item in pcl_values:
        try:
            code = int(item['i'])
            qty = int(item['q'])
            pcl_map[code] = qty
        except:
            continue
    threshold_map = {0:210, 1:180, 2:130, 3:80}
    check_list = [1112, 1131, 1143, 1145, 1158, 1165, 1167, 1171, 1197,
                  111119, 111121, 111122, 111129, 111130, 111131, 111132, 111133,
                  111142, 111143, 111144, 111145, 111146, 111147, 111148, 111149,
                  111150, 111155, 111160, 111161, 111167, 111170, 111171, 111172,
                  111174, 111175, 111179, 111181, 111182, 111185, 111188, 111190,
                  22000000, 22000020, 22000040, 22000050, 22000060, 22000080, 22000090,
                  22000100, 22000120, 22000150, 22000190, 22000200, 22000210, 22000220,
                  22000230, 22000240, 22000250, 22000260, 22000280, 22000290, 22000310,
                  22000320, 22000330, 22000340, 22000350, 22000370, 22000380, 22000410,
                  22000440, 22000450, 22000460, 22000470, 22000480, 22000510, 22000520,
                  22000530, 22000540, 22000550, 22000560, 22000570, 22000580, 22000590,
                  22000610, 22000620, 22000630, 22000640, 22000650, 22000660, 22000670,
                  22000680, 22000690, 22000700, 22000710, 22000720, 22000730, 22000740,
                  22000750, 22000760, 22000770, 22000780, 22000790, 22000800, 22000810,
                  22000820, 22000830, 22000840, 22000850, 22000860, 22000880, 22000890,
                  22000900, 22000910, 22000920, 22000930, 22000940, 22000950, 22000960,
                  22000970, 22000980, 22000990, 22001000, 22001010, 22001020, 22001270,
                  22001280]
    selected_candidates = []
    for plant in pl_values:
        try:
            plant_code = int(plant['i'])
            level = int(plant.get('s', 0))  
        except:
            continue
        frag_code = get_frag_code(plant_code)
        if frag_code not in pcl_map:
            continue
        avail = pcl_map[frag_code]
        if level < 5:
            threshold = threshold_map.get(level, 0)
            if avail < threshold:
                continue
            remainder = avail - threshold
        else:
            remainder = avail
        available = remainder // 2
        if available < 2:
            continue
        conv_count = 2 if frag_code in check_list else (5 if available >= 5 else (4 if available >= 4 else (3 if available >= 3 else 2)))
        selected_candidates.append({
            "frag_code": frag_code,
            "conv_count": conv_count,
            "level": level,
            "avail": avail,
            "conv_available": available
        })
    candidate_set = {}
    for candidate in selected_candidates:
        frag = candidate["frag_code"]
        if frag in candidate_set:
            candidate_set[frag]["level"] = min(candidate_set[frag]["level"], candidate["level"])
            candidate_set[frag]["avail"] = max(candidate_set[frag]["avail"], candidate["avail"])
        else:
            candidate_set[frag] = {"level": candidate["level"], "avail": candidate["avail"]}
    if candidate_set:
        print("已选转基因候选碎片：")
        for frag, info in candidate_set.items():
            name = 植物碎片字典.get(str(frag))
            output = name if name is not None else str(frag)
            print(f"{output} - 等级: {info['level'] + 1}, 碎片数: {info['avail']}")
    else:
        print("没有符合条件的植物碎片。")
        return
    confirm = input("是否开始转基因？(1确认): ").strip().upper()
    if confirm != "1":
        print("停止转基因。")
        return
    total_converted = {}
    for candidate in selected_candidates:
        frag_code = candidate["frag_code"]
        conv_count = candidate["conv_count"]
        conv_available = candidate["conv_available"]
        rounds = math.ceil(conv_available / conv_count)
        for r in range(rounds):
            l_list = [frag_code] * conv_count + [0] * (5 - conv_count)
            data_v323 = {
                "req": "V323",
                "e": {"ad": "0", "l": l_list, "pi": pi, "sk": sk, "t": "0", "ui": ui},
                "ev": 1
            }
            _, resp_v323 = send_加密发送_解密响应(data_v323)
            if isinstance(resp_v323, dict) and "gl" in resp_v323:
                resp_obj = resp_v323
            else:
                print("响应解析错误：找不到 gl 字段")
                print("完整响应：", resp_v323)
                continue
            for item in resp_obj["gl"]:
                frag_conv_code = item.get("i")
                qty_conv = item.get("q")
                name = 植物碎片字典.get(str(frag_conv_code))
                output = name if name is not None else str(frag_conv_code)
                print(f"获得: {output} 数量: {qty_conv}")
                total_converted[frag_conv_code] = total_converted.get(frag_conv_code, 0) + qty_conv
    print("总共获得的碎片:")
    for code, q in total_converted.items():
        name = 植物碎片字典.get(str(code))
        output = name if name is not None else str(code)
        print(f"{output} 数量: {q}")
    _, decrypted_json_after = send_加密发送_解密响应(data_V316)
    new_pcl_map = {}
    for item in decrypted_json_after.get("pcl", []):
        try:
            code = int(item.get("i"))
            qty = int(item.get("q"))
            new_pcl_map[code] = qty
        except:
            continue
    new_candidate_set = {}
    for plant in decrypted_json_after.get("pl", []):
        try:
            plant_code = int(plant["i"])
            level = int(plant.get("s", 0))
        except:
            continue
        frag_code = get_frag_code(plant_code)
        if frag_code not in new_pcl_map:
            continue
        avail = new_pcl_map[frag_code]
        if level < 5:
            threshold = threshold_map.get(level, 0)
            if avail < threshold:
                continue
            remainder = avail - threshold
        else:
            remainder = avail
        if (remainder // 2) < 2:
            continue
        if frag_code in new_candidate_set:
            new_candidate_set[frag_code]["level"] = min(new_candidate_set[frag_code]["level"], level)
            new_candidate_set[frag_code]["avail"] = max(new_candidate_set[frag_code]["avail"], avail)
        else:
            new_candidate_set[frag_code] = {"level": level, "avail": avail}
    print("当前剩余满足转基因条件的碎片：")
    for frag, info in new_candidate_set.items():
        name = 植物碎片字典.get(str(frag))
        output = name if name is not None else str(frag)
        print(f"{output} - 等级: {info['level'] + 1}, 碎片数: {info['avail']}")
def make_官服改密():
    account = input("请输入账号: ").strip()
    old_pass = input("请输入旧密码: ").strip()
    token, user_id = login_and_get_token_userid(account, old_pass)
    if not token or not user_id:
        print("登录失败，无法修改密码。")
        return
    new_pass = input("请输入新密码: ").strip()
    payload = f"token={token}&userId={user_id}&oldPassword={old_pass}&newPassword={new_pass}"
    url = "http://tgpay.talkyun.com.cn/tw-sdk/sdk-api/user/modifyPassWord"
    headers1 = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; 23013RK7C Build/TKQ1.220905.001)',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip, deflate'

    }
    resp = requests.post(url, data=payload, headers=headers1)
    if resp.status_code == 403:
        print("你被锁ip")
        return
    if resp.status_code != 200:
        print(f"HTTP请求失败，状态码: {resp.status_code}")
        return
    if "密码修改成功" in resp.text:
        print("密码修改成功")
    else:
        print("修改密码失败，响应如下：")
        print(resp.text)
def login_and_get_token_userid(account: str, password: str, last_token: str = ""):
    import requests, hashlib, json
    appkey = "b0b29851-b8a1-4df5-abcb-a8ea158bea20"
    head_plain = json.dumps({
        "appId": 109,
        "channelId": 208,
        "sdkVersion": "2.0.0"
    }, separators=(',', ':'))
    login_dict = {
        "password": md5(password),
        "phone": account
    }
    if last_token:
        login_dict["token"] = last_token
    login_plain = json.dumps(login_dict, separators=(',', ':'))
    head_enc = des_encrypt(head_plain)
    login_enc = des_encrypt(login_plain)
    md5_val = hashlib.md5((login_plain + appkey).encode('utf-8')).hexdigest()
    
    url = "http://tgpay.talkyun.com.cn/tw-sdk/sdk-api/user/login"
    data = {"head": head_enc, "login": login_enc, "md5": md5_val}
    headers2 = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; 22021211RC Build/TKQ1.220807.001)"
    }
    resp = requests.post(url, data=data, headers=headers2)
    if resp.status_code == 200:
        first = des_decrypt(resp.text.strip())
        content_hex = json.loads(first)["content"]
        second = des_decrypt(content_hex)
        user_info = json.loads(second)
        token = user_info["token"].strip()
        user_id = str(user_info["userId"])
        print("登录成功")
        print("token:", token)
        return token, user_id
    else:
        try:
            decrypted = des_decrypt(resp.text.strip())
            print("登录失败，返回信息：")
            print(decrypted)
        except Exception as e:
            print("登录失败，响应解析错误：", resp.text)
        return None, None

def make_超Z榜单():
    data = {"req":"V303","e":{"al":[{"id":10704,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":"newest_version"},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    response = decrypted_json[0] if isinstance(decrypted_json, list) else decrypted_json

    # 判断是否包含 "data" 字段
    if "data" not in response:
        print("进入超Z榜单失败：", response)
        return

    inner_data = json.loads(response["data"])
    
    print("超Z榜单：")
    lb_list = inner_data.get("lb", [])
    for rank, item in enumerate(lb_list, 1):
        name = item.get("n", "未知")
        trophy = item.get("s", 0)
        print(f"{rank}. 名称: {name}, 奖杯数: {trophy}")

def make_响叮当榜单():
    data = {"req":"V1090","e":{"o":"120","pi":pi,"sk":sk,"ui":ui},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    response = decrypted_json[0] if isinstance(decrypted_json, list) else decrypted_json

    if "grl" not in response:
        print("进入响叮当榜单失败：", response)
        return

    rl = response["grl"].get("rl", [])
    
    print("响叮当榜单：")
    for item in rl:
        rank = item.get("rank", "未排名")
        name = item.get("n", "未知")
        score = item.get("s", 0)
        pi_value = item.get("pi", "")
        print(f"排名: {rank}, 名称: {name}, 分数: {score}, pi: {pi_value}")

def make_庭院榜单():
    board_map = {"1": "2", "2": "1", "3": "0"}
    choice = input("请选择榜单类型(1: 周榜, 2: 月榜, 3: 总榜): ").strip()
    if choice not in board_map:
        print("输入无效！")
        return
    k_val = board_map[choice]
    
    # 构造公共请求数据
    base_data = {
        "c": "100",
        "f": "0",
        "k": k_val,
        "pi": pi,
        "pk": "0,1,2,3,4,5,6,7",
        "s": "0",
        "sk": sk,
        "t": "1",
        "ui": ui,
        "w": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"
    }
    
    data = {"req": "V723", "e": base_data, "ev": 1}
    _, decrypted_json = send_加密发送_解密响应(data)
    
    if "ls" not in decrypted_json:
        print("请求失败：", decrypted_json)
        return
    
    ls_list = decrypted_json["ls"]
    print("\n庭院榜单：")
    for idx, item in enumerate(ls_list, 1):
        t_str = item.get("t", "")
        try:
            t_data = json.loads(t_str) if t_str else {}
        except Exception:
            t_data = {}
        print(f"排名：{idx}")
        print(f"关卡ID：{item.get('i','')}")
        print(f"关卡名：{item.get('n','')}")
        print(f"点赞数：{item.get('l','')}")
        print(f"游玩数：{item.get('pc','')}")
        print(f"用户名：{item.get('an','')}")
        print(f"用户ID/pi：{item.get('ai','')}")
        print(f"发布时间：{item.get('ca','')}\n")
def make_查询庭院关卡():
    level_id = input("请输入庭院关卡ID: ").strip()

    # 构造请求数据
    data = {
        "req": "V726",
        "e": {
            "id": level_id,
            "pi": pi,
            "pk": "",
            "sk": sk,
            "ui": ui,
            "w": ""
        },
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data)

    if not isinstance(decrypted_json, dict) or not decrypted_json:
        print("请求失败：", decrypted_json)
        return

    print("查询结果：")
    print(f"关卡ID: {decrypted_json.get('i', '')}")
    print(f"关卡名: {decrypted_json.get('n', '')}")
    print(f"点赞数: {decrypted_json.get('l', '')}")
    print(f"游玩数: {decrypted_json.get('pc', '')}")
    print(f"作者UI: {decrypted_json.get('ai', '')}")
    print(f"用户名: {decrypted_json.get('an', '')}")
    print(f"发布时间: {decrypted_json.get('ca', '')}")

    # 处理评价字段 t：键1代表难度适中，2代表内容丰富，3代表设置合理
    t_field = decrypted_json.get("t", {})
    if isinstance(t_field, dict):
        print("评价:")
        print(f"  难度适中: {t_field.get('1', 0)}")
        print(f"  内容丰富: {t_field.get('2', 0)}")
        print(f"  设置合理: {t_field.get('3', 0)}")
    else:
        print("评价数据不可用")
def make_删除关卡():
    selected_id = input("请输入庭院关卡ID: ").strip()
    data = {"req": "V727", "e": {"id": selected_id, "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    send_加密发送_拼接提示(data, f"删除关卡 {selected_id} 成功")

def make_无尽任务():
    data = {"req":"V303","e":{"al":[{"id":10622,"abi":0,"type":1,"config_version":1}],"ci":"0","cs":"0","pack":"com.popcap.pvz2xkpx","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        inner_data = json.loads(decrypted_json[0]["data"])
        bonuses = inner_data.get("taskBonusList", None)
        if bonuses is None:
            print("未找到 taskBonusList，内部数据为：", inner_data)
        else:
            for bonus in bonuses:
                if isinstance(bonus, dict):
                    tk = bonus.get("tId", "")
                elif isinstance(bonus, list) and len(bonus) and isinstance(bonus[0], dict):
                    tk = bonus[0].get("tId", "")
                else:
                    print("bonus 数据格式异常：", bonus)
                    continue

                data_task = {
                    "req": "V1158",
                    "e": {
                        "pi": pi,
                        "sk": sk,
                        "tk": tk,
                        "ui": ui
                    },
                    "ev": 1
                }
                send_加密发送_拼接提示(data_task, f"领取任务奖励 {tk}")
    except Exception as e:
        print("处理任务奖励时出现错误：", e)

#===========================购买======================
def make_潘妮商店():
    global pi, sk, ui
    data = {
        "req": "V222",
        "e": {"p": {}, "pi": pi, "rv": "5", "sk": sk, "t": "1", "ui": ui},
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        shop_info = json.loads(decrypted_json['j'])
    except (KeyError, json.JSONDecodeError) as e:
        print("解析潘妮商店响应失败:", e)
        return
    sis = shop_info.get("sis", [])
    if not sis:
        print("潘妮商店没有商品")
        return
    products = []
    print("潘妮商店商品列表：")
    for item in sis:
        item_id = str(item.get("id"))
        purchase_currency = item.get("pt", "")
        price = item.get("p", 0)
        remaining = item.get("lt", 0)
        total_cost = item.get("tp", 0)
        if item_id in 植物碎片字典:
            name = 植物碎片字典[item_id]
        elif item_id in 植物装扮碎片字典:
            name = 植物装扮碎片字典[item_id]
        else:
            name = "未知商品"
        if purchase_currency == "gold":
            currency_name = "金币"
        elif purchase_currency == "gem":
            currency_name = "钻石"
        else:
            currency_name = purchase_currency
        products.append((item_id, name, currency_name, price, remaining, total_cost))
    for idx, prod in enumerate(products, start=1):
        print(f"{idx}: {prod[1]} | 货币: {prod[2]} | 单价: {prod[3]} | 剩余: {prod[4]} | 总花费: {prod[5]}")
    
    try:
        choice = int(input("请选择购买的商品序号："))
    except ValueError:
        print("输入无效！")
        return
    if choice < 1 or choice > len(products):
        print("序号超出范围")
        return
    chosen_item = products[choice-1]
    chosen_id = chosen_item[0]
    print(f"你选择购买：{chosen_item[1]}")
    try:
        buy_times = int(input("请输入购买次数: "))
    except ValueError:
        print("购买次数无效")
        return
    remaining = int(chosen_item[4])
    if buy_times > remaining:
        print(f"购买次数超过剩余数量 {remaining}")
        return
    package_type = "3" if buy_times == remaining else "2"
    for i in range(buy_times):
        purchase_data = {
            "req": "V222",
            "e": {
                "p": {"id": chosen_id},
                "pi": pi,
                "rv": "5",
                "sk": sk,
                "t": package_type,
                "ui": ui
            },
            "ev": 1
        }
        send_加密发送_拼接提示(purchase_data, f"潘妮商店购买 {chosen_item[1]} 第 {i+1} 次")
def make_水晶商店():
    data = {"req":"V303","e":{"al":[{"id":10809,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        if isinstance(decrypted_json, list):
           shop_info = json.loads(decrypted_json[0]["data"])
        else:
           shop_info = json.loads(decrypted_json["data"])
    except (KeyError, ValueError) as e:
        print("解析水晶商店响应失败:", e)
        return
    si = shop_info.get("si", [])
    if not si or len(si) < 6:
        print("水晶商店数据异常")
        return

    category_names = ["远程植物", "肉盾", "近战", "消耗", "辅助", "装扮"]
    flat_items = []
    print("水晶商店商品列表：")
    idx = 0
    for cat_idx, group in enumerate(si):
        for sub_idx, item in enumerate(group):
            item_id = str(item.get("i"))
            cost = item.get("c", 0)
            if item_id in 植物字典:
                name = 植物字典[item_id]
            elif item_id in 植物装扮字典:
                name = 植物装扮字典[item_id]
            else:
                continue
            flat_items.append((cat_idx, sub_idx, name, cost))
            print(f"{idx}: {name} - {category_names[cat_idx]}, 花费水晶: {cost}")
            idx += 1

    try:
        choice = int(input("请选择购买的商品编号："))
    except ValueError:
        print("输入无效！")
        return
    if choice < 0 or choice >= len(flat_items):
        print("编号超出范围")
        return

    chosen_cat, chosen_sub, chosen_name, cost = flat_items[choice]
    print(f"你选择购买：{chosen_name} - {category_names[chosen_cat]}")
    purchase_package = {
        "req": "V392",
        "e": {
            "ci": "0",
            "gi": str(chosen_cat),
            "mi": "23097",
            "pi": pi,
            "q": str(chosen_sub),
            "si": "9",
            "sk": sk,
            "ui": ui,
        },
        "ev": 1
    }
    send_加密发送_拼接提示(purchase_package, f"水晶商店购买 {chosen_name}")
    print(f"已购买 {chosen_name}")
def make_超Z商店():
    data = {"req":"V382","e":{"ad":"0","c":"0","is":"0","pi":pi,"s":"1","sk":sk,"ui":ui},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        response = decrypted_json  
    except Exception as e:
        print("解析超Z商店响应失败:", e)
        return
    si_list = response.get("si", [])
    if not si_list:
        print("超Z商店没有商品")
        return
    print("超Z商店商品列表：")
    products = []
    idx = 1
    for item in si_list:
        oi = str(item.get("oi"))
        q_value = item.get("q")
        price = item.get("p", 0)
        purchasable = item.get("l", 0)
        if oi in 植物碎片字典:
            name = 植物碎片字典[oi]
        elif oi in 植物装扮碎片字典:
            name = 植物装扮碎片字典[oi]
        else:
            name = "未知商品"
        products.append((oi, name, q_value, price, purchasable))
        status_str = "可购" if purchasable == 1 else "不可购"
        print(f"{idx}: {name} | 数量: {q_value} | 价格: {price} | {status_str}")
        idx += 1
    try:
        choice = int(input("请选择购买的商品序号："))
    except ValueError:
        print("输入无效")
        return
    if choice < 1 or choice > len(products):
        print("序号超出范围")
        return
    chosen_item = products[choice - 1]
    chosen_oi, chosen_name, chosen_q, chosen_price, _ = chosen_item
    print(f"你选择购买: {chosen_name}")
    purchase_data = {
        "req": "V383",
        "e": {
            "oi": chosen_oi,
            "pi": pi,
            "q": str(chosen_q),
            "sk": sk,
            "ui": ui
        },
        "ev": 1
    }
    send_加密发送_拼接提示(purchase_data, f"超Z商店购买 {chosen_name}")
def make_庭院商店():
    data = {"req":"V303","e":{"al":[{"id":10840,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        shop_info = json.loads(decrypted_json[0]["data"])
    except (KeyError, ValueError) as e:
        print("解析庭院商店响应失败:", e)
        return
    shop_list = shop_info.get("shopList", [])
    playToken = shop_info.get("playToken", 0)
    writeToken = shop_info.get("writeToken", 0)
    if not shop_list:
        print("庭院商店没有商品")
        return
    print(f"游玩币数量: {playToken}")
    print(f"紫币数量: {writeToken}")
    print("--------------------")
    print("庭院商店商品列表：")
    products = []
    idx = 1
    for item in shop_list:
        code = str(item.get("i"))
        q_val = item.get("q")
        max_buy = item.get("m")
        price = item.get("c", 0)
        ct = item.get("ct")
        own = item.get("own", 0)
        if code in 植物碎片字典:
            name = 植物碎片字典[code]
        elif code in 道具字典:
            name = 道具字典[code]
        elif code in 植物装扮碎片字典:
            name = 植物装扮碎片字典[code]
        else:
            name = "未知商品"
        products.append({
            "code": code,
            "name": name,
            "q": q_val,
            "m": max_buy,
            "c": price,
            "ct": ct,
            "own": own
        })
        if ct == 23403:
            currency = "紫币"
        elif ct == 23402:
            currency = "游玩币"
        else:
            currency = str(ct)
        print(f"{idx}: {name} | 数量: {q_val} | 最大购买数: {max_buy} | 单价: {price} | 所需货币: {currency} | 已购买: {own}")
        idx += 1

    try:
        choice = int(input("请选择购买的商品序号："))
    except ValueError:
        print("输入无效！")
        return
    if choice < 1 or choice > len(products):
        print("序号超出范围")
        return

    chosen = products[choice - 1]
    print(f"你选择购买：{chosen['name']}")
    try:
        purchase_total = int(input("请输入购买数量："))
    except ValueError:
        print("购买数量输入无效")
        return
    purchase_requests = []
    if purchase_total >= 10:
        batches = purchase_total // 10
        remainder = purchase_total % 10
        for _ in range(batches):
            purchase_requests.append("10")
        for _ in range(remainder):
            purchase_requests.append("1")
    else:
        for _ in range(purchase_total):
            purchase_requests.append("1")
    for idx_req, qty in enumerate(purchase_requests, start=1):
        purchase_data = {
            "req": "V392",
            "e": {
                "ci": str(chosen["c"]),
                "gi": chosen["code"],
                "mi": str(chosen["ct"]),
                "pi": pi,
                "q": qty,
                "si": "11",
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        send_加密发送_拼接提示(purchase_data, f"庭院商店购买 {chosen['name']} 第 {idx_req} 次")
    print(f"已尝试购买 {purchase_total} 次 {chosen['name']}")
def make_聚宝盆商店():
    data = {"req":"V303","e":{"al":[{"id":10863,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        if isinstance(decrypted_json, list):
            shop_info = json.loads(decrypted_json[0]["data"])
        else:
            shop_info = json.loads(decrypted_json["data"])
    except (KeyError, ValueError) as e:
        print("解析聚宝盆商店响应失败:", e)
        return

    spn = shop_info.get("spn", 0)
    pln = shop_info.get("pln", 0)
    level = shop_info.get("level", 0)
    print(f"当前货币数量: {spn}")
    print(f"抽取次数: {pln}")
    print(f"聚宝盆等级: {level}")
    print("--------------------")
    
    shop_list = shop_info.get("shop_list", [])
    if not shop_list:
        print("聚宝盆商店没有商品")
        return
    products = []
    idx = 1
    for item in shop_list:
        code = str(item.get("i"))
        q_value = item.get("q", 0)
        max_buy = item.get("m", 0)
        cost = item.get("c", 0)
        req_level = item.get("li", 0)
        can_buy = item.get("l", 0)
        currency_code = item.get("t")
        if code in 道具字典:
            name = 道具字典[code]
        elif code in 植物碎片字典:
            name = 植物碎片字典[code]
        else:
            name = "未知商品"
        products.append({
            "i": code,
            "name": name,
            "q": q_value,
            "m": max_buy,
            "c": cost,
            "li": req_level,
            "l": can_buy,
            "t": currency_code
        })
        status = "可购" if can_buy == 1 else "不可购"
        print(f"{idx}: {name} | 数量: {q_value} | 最大购买数: {max_buy} | 单价: {cost} | 所需等级: {req_level} | {status}")
        idx += 1

    try:
        choice = int(input("请选择购买的商品序号: "))
    except ValueError:
        print("输入无效")
        return
    if choice < 1 or choice > len(products):
        print("序号超出范围")
        return
    selected = products[choice - 1]
    print(f"你选择购买: {selected['name']}")
    try:
        purchase_total = int(input("请输入购买数量: "))
    except ValueError:
        print("购买数量无效")
        return

    purchase_data = {
        "req": "V392",
        "e": {
            "ci": str(selected["c"]),
            "gi": str(choice - 1),
            "mi": str(selected["t"]),
            "pi": pi,
            "q": str(purchase_total),
            "si": "15",
            "sk": sk,
            "ui": ui
        },
        "ev": 1
    }
    send_加密发送_拼接提示(purchase_data, f"聚宝盆商店购买 {selected['name']}")
    print(f"已尝试购买 {purchase_total} 次 {selected['name']}")
def make_同游商店():
    data = {"req":"V303","e":{"al":[{"id":10892,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        if isinstance(decrypted_json, list):
            shop_info = json.loads(decrypted_json[0]["data"])
        else:
            shop_info = json.loads(decrypted_json["data"])
    except (KeyError, ValueError) as e:
        print("解析同游商店响应失败:", e)
        return

    tokenCurCnt = shop_info.get("tokenCurCnt", 0)
    itemNum = shop_info.get("itemNum", 0)
    print(f"获得的同游币: {tokenCurCnt}")
    print(f"剩余同游币: {itemNum}")
    print("--------------------")

    shop_list = shop_info.get("shopList", [])
    if not shop_list:
        print("同游商店没有商品")
        return

    products = []
    idx = 1
    for item in shop_list:
        price = item.get("price", 0)
        limit = item.get("limit", 0)
        code = str(item.get("i"))
        q_value = item.get("q", 0)

        if code in 植物装扮字典:
            name = 植物装扮字典[code]
        elif code in 道具字典:
            name = 道具字典[code]
        elif code in 植物碎片字典:
            name = 植物碎片字典[code]
        else:
            name = "未知商品"
        products.append({
            "i": code,
            "name": name,
            "price": price,
            "limit": limit,
            "q": q_value  
        })
        print(f"{idx}: {name} | 价格: {price} | 数量: {q_value} | 限购: {limit}")
        idx += 1

    try:
        choice = int(input("请选择购买的商品序号: "))
    except ValueError:
        print("输入无效")
        return
    if choice < 1 or choice > len(products):
        print("序号超出范围")
        return
    selected = products[choice - 1]
    print(f"你选择购买: {selected['name']}")
    try:
        loop_times = int(input("请输入循环购买次数: "))
    except ValueError:
        print("购买次数无效")
        return
    for idx_req in range(1, loop_times + 1):
        purchase_data = {
            "req": "V392",
            "e": {
                "ci": str(selected["price"]),
                "gi": str(selected["i"]),
                "mi": "300055",
                "pi": pi,
                "q": str(selected["q"]),
                "si": "17",
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        send_加密发送_拼接提示(purchase_data, f"同游商店购买 {selected['name']} 第 {idx_req} 次")
    print(f"已尝试购买 {loop_times} 次 {selected['name']}")
def make_双人商店():
    data = {"req":"V835","e":{"c":"0","pi":pi,"s":"1","sk":sk,"ui":ui},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        # 如果响应为列表则取第一个元素
        shop_info = decrypted_json[0] if isinstance(decrypted_json, list) else decrypted_json
    except Exception as e:
        print("解析双人商店响应失败:", e)
        return
    haveMoney = shop_info.get("haveMoney", 0)
    shopItems = shop_info.get("shopItems", [])
    reset_time = shop_info.get("shopResetAt", "")
    print(f"当前紫币数: {haveMoney}")
    print(f"商店重置时间: {reset_time}")
    print("--------------------")
    if not shopItems:
        print("双人商店没有商品")
        return
    products = []
    idx = 1
    for item in shopItems:
        objId = item.get("objId")
        quantity = item.get("quantity", 0)
        price = item.get("price", 0)
        limit = item.get("limit", 0)
        code = str(objId)
        if code in 双人对决僵尸字典:
            name = 双人对决僵尸字典[code]
        else:
            name = "未知僵尸"
        products.append({
            "objId": objId,
            "name": name,
            "quantity": quantity,
            "price": price,
            "limit": limit
        })
        print(f"{idx}: {name} | 数量: {quantity} | 价格: {price} | 限购: {limit}")
        idx += 1

    try:
        choice = int(input("请选择购买的商品序号: "))
    except ValueError:
        print("输入无效")
        return
    if choice < 1 or choice > len(products):
        print("序号超出范围")
        return
    selected = products[choice - 1]
    print(f"你选择购买: {selected['name']}")
    try:
        times = int(input("请输入要循环购买的次数(每次只能购买1个): "))
    except ValueError:
        print("购买次数输入无效")
        return
    for idx_req in range(1, times + 1):
        purchase_data = {
            "req": "V392",
            "e": {
                "ci": str(selected["price"]),  
                "gi": str(choice - 1),           
                "mi": "23243",                 
                "pi": pi,
                "q": "1",                      
                "si": "14",                    
                "sk": sk,
                "ui": ui
            },
            "ev": 1
        }
        send_加密发送_拼接提示(purchase_data, f"双人商店购买 {selected['name']} 第 {idx_req} 次")
    print(f"已尝试购买 {times} 次 {selected['name']}")

def make_聚宝盆收获():
    data = {"req":"V869","e":{"index":"2","pi":pi,"sk":sk,"t":"0","ui":ui},"ev":1}
    send_加密发送_拼接提示(data, "聚宝盆收获")

def make_聚宝盆抽奖():
    total = int(input("请输入抽奖次数: "))
    total_rewards = {}  

    def do_draw(t_value, draw_num, mode_desc):
        data = {"req": "V867", "e": {"pi": pi, "sk": sk, "t": t_value, "ui": ui}, "ev": 1}
        for i in range(draw_num):
            _, response = send_加密发送_解密响应(data)
            print(f"【第 {i+1} 次 {mode_desc}】")
            if response.get("code") == 0:
                pn = response.get("pn")
                print(f"剩余抽奖币：{pn}")
                items = response.get("bl", [])
                if items:
                    print("获得物品：")
                    for item in items:
                        code = str(item.get("i"))
                        quantity = item.get("q", 0)
                        if code in 道具字典:
                            item_name = 道具字典[code]
                            print(f"  获得：{item_name} 数量：{quantity}")
                        elif code in 植物碎片字典:
                            item_name = 植物碎片字典[code]
                            print(f"  获得：{item_name} 数量：{quantity}")
                        else:
                            item_name = f"未知物品({code})"
                            print(f"  获得：{item_name} 数量：{quantity}")
                        total_rewards[item_name] = total_rewards.get(item_name, 0) + quantity
                else:
                    print("未获得任何物品")
            else:
                print("抽奖失败")
            print("-" * 50)
            time.sleep(0.5)

    if total < 10:
        print("采用单抽模式")
        do_draw("0", total, "单抽")
    else:
        tens = total // 10
        remainder = total % 10
        print(f"将执行 {tens} 次 10连抽和 {remainder} 次单抽")
        do_draw("1", tens, "10连抽")
        if remainder > 0:
            do_draw("0", remainder, "单抽")
    
    print("抽奖操作结束")
    print("本次累计获得奖励：")
    if total_rewards:
        for reward, qty in total_rewards.items():
            print(f"{reward} x {qty}")
    else:
        print("未获得任何奖励")

def make_秘宝抽奖():
    total_rewards = {} 
    def process_draw_response(response):
        if response.get("b"):
            rewards = response.get("b")
            for reward in rewards:
                code = str(reward.get("i"))
                quantity = reward.get("q", 0)
                probability = reward.get("w")
                if code in 植物字典:
                    item_name = 植物字典[code]
                elif code in 植物碎片字典:
                    item_name = 植物碎片字典[code]
                elif code in 植物装扮碎片字典:
                    item_name = 植物装扮碎片字典[code]
                elif code in 道具字典:
                    item_name = 道具字典[code]
                else:
                    item_name = f"未知物品 ({code})"
                print(f"获得 {item_name} 数量: {quantity}, 概率: {probability}")
                total_rewards[item_name] = total_rewards.get(item_name, 0) + quantity
        else:
            print("未获得任何物品。")
    
        p_field = response.get("p", {})
        diamonds = p_field.get("g1", "0")
        uk_value = p_field.get("uk", "")
        print(f"钻石数: {diamonds}")
        print(f"uk值: {uk_value}")
    
        mi_field = response.get("mi", {})
        if mi_field:
            secret_code = str(mi_field.get("i"))
            secret_quantity = mi_field.get("q", 0)
            if secret_code in 植物字典:
                secret_name = 植物字典[secret_code]
            elif secret_code in 植物碎片字典:
                secret_name = 植物碎片字典[secret_code]
            elif secret_code in 植物装扮碎片字典:
                secret_name = 植物装扮碎片字典[secret_code]
            elif secret_code in 道具字典:
                secret_name = 道具字典[secret_code]
            else:
                secret_name = f"未知物品 ({secret_code})"
            print(f"秘宝券: {secret_name} 数量: {secret_quantity}")
            total_rewards[f"秘宝券-{secret_name}"] = total_rewards.get(f"秘宝券-{secret_name}", 0) + secret_quantity

    # 发送基础请求，获取当前密保抽奖基础信息
    data = {
        "req": "V303",
        "e": {
            "al": [{"id": 10788, "abi": 0, "type": 1, "config_version": 1}],
            "ci": "93",
            "cs": "0",
            "pack": "com.popcap.pvz2cthdbk",
            "pi": pi,
            "rv": "5",
            "sk": sk,
            "ui": ui,
            "v": newest_version
        },
        "ev": 1
    }
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        inner_data = json.loads(decrypted_json[0]["data"])
    except Exception as e:
        print("解密数据解析失败:", e)
        return

    print("【密保抽奖基础信息】")
    oi = str(inner_data.get("oi"))
    if oi in 植物字典:
        oi_name = 植物字典[oi]
    else:
        oi_name = f"未知植物 ({oi})"
    print(f"当前已选植物：{oi_name}")
    
    print("抽奖候选物品：")
    for item in inner_data.get("si", []):
        code = str(item.get("i"))
        quantity = item.get("q")
        probability = item.get("w")
        if code in 植物碎片字典:
            item_name = 植物碎片字典[code]
        elif code in 植物装扮碎片字典:
            item_name = 植物装扮碎片字典[code]
        elif code in 道具字典:
            item_name = 道具字典[code]
        else:
            item_name = f"未知物品 ({code})"
        print(f"  {item_name} 数量: {quantity}, 概率: {probability}")
    
    print("主位植物候选：")
    ois = inner_data.get("ois", [])
    if not isinstance(ois, list):
        print("主位植物候选数据格式错误。")
        ois = []
    for idx, plant_code in enumerate(ois, start=1):
        plant_code = str(plant_code)
        if plant_code in 植物字典:
            plant_name = 植物字典[plant_code]
        else:
            plant_name = f"未知植物 ({plant_code})"
        print(f"  {idx}. {plant_name}")
    
    selection = input("请输入要选择的主位植物序号（留空则跳过选择）: ").strip()
    selected_plant = None
    if selection:
        try:
            sel_index = int(selection)
            if 1 <= sel_index <= len(ois):
                selected_plant = str(ois[sel_index - 1])
                print(f"你选择的主位植物代码：{selected_plant}")
                data_select = {
                    "req": "V917",
                    "e": {
                        "p": selected_plant,
                        "pi": pi,
                        "sk": sk,
                        "ui": ui
                    },
                    "ev": 1
                }
                send_加密发送_拼接提示(data_select, f"选择主位植物 {selected_plant}")
                _, new_decrypted_json = send_加密发送_解密响应(data)
                new_inner_data = json.loads(new_decrypted_json[0]["data"])
                new_oi = str(new_inner_data.get("oi"))
                if new_oi == selected_plant:
                    print("主位植物选择确认成功！")
                else:
                    print("主位植物选择未生效，请重新选择。")
            else:
                print("输入序号超过候选范围，跳过选择。")
        except Exception as e:
            print("输入错误，跳过主位植物选择。")
    else:
        print("跳过主位植物选择。")
    
    total_draws_input = input("请输入抽奖次数 (直接回车退出): ").strip()
    if not total_draws_input:
        print("未输入抽奖次数，退出抽奖。")
        return
    try:
        total_draws = int(total_draws_input)
    except Exception as e:
        print("抽奖次数输入错误，退出。")
        return

    draw_responses = []
    print("开始抽奖……")
    if total_draws < 10:
        for i in range(total_draws):
            data_draw = {"req": "V916", "e": {"pi": pi, "sk": sk, "t": "2", "ui": ui}, "ev": 1}
            _, response = send_加密发送_解密响应(data_draw)
            draw_responses.append(response)
            print(f"【第{i+1}次 单抽】")
            process_draw_response(response)
            time.sleep(1)
    else:
        tens = total_draws // 10
        remainder = total_draws % 10
        for i in range(tens):
            data_draw = {"req": "V916", "e": {"pi": pi, "sk": sk, "t": "3", "ui": ui}, "ev": 1}
            _, response = send_加密发送_解密响应(data_draw)
            draw_responses.append(response)
            print(f"【第{i+1}次 10连抽】")
            process_draw_response(response)
            time.sleep(1)
        if remainder:
            for i in range(remainder):
                data_draw = {"req": "V916", "e": {"pi": pi, "sk": sk, "t": "2", "ui": ui}, "ev": 1}
                _, response = send_加密发送_解密响应(data_draw)
                draw_responses.append(response)
                print(f"【额外第{i+1}次 单抽】")
                process_draw_response(response)
                time.sleep(1)
    
    print("【全部抽奖结果】")
    for idx, response in enumerate(draw_responses, start=1):
        print(f"抽奖 {idx}:")
        process_draw_response(response)
        print("-" * 50)

    print("累计获得奖励：")
    if total_rewards:
        for reward, qty in total_rewards.items():
            print(f"{reward} x {qty}")
    else:
        print("未获得任何奖励")

def make_砸罐子():
    data = {"req": "V303","e": {"al": [{"id": 10790, "abi": 0, "type": 1, "config_version": 1}],"ci": "91","cs": "0","pack": "com.popcap.pvz2cthd4399","pi": pi,"sk": sk,"ui": ui,"v": newest_version},"ev": 1}
    success, decrypted_json = send_加密发送_解密响应(data)
    if not success:
        print("请求初始信息失败！")
        return
    try:
        if not decrypted_json or not isinstance(decrypted_json, list):
            print("响应数据格式错误！")
            return
        data_str = decrypted_json[0].get("data")
        if not data_str:
            print("响应中缺失 data 字段！")
            return
        inner_data = json.loads(data_str)
    except Exception as e:
        print("解析初始响应数据失败:", e)
        return

    print("【砸罐子初始信息】")
    rl_list = inner_data.get("rl", [])
    if rl_list:
        print("罐子奖励列表：")
        for item in rl_list:
            code = str(item.get("i", ""))
            quantity = item.get("q", 0)
            probability = item.get("w", "N/A")
            if code in 植物字典:
                item_name = 植物字典[code]
            elif code in 植物装扮字典:
                item_name = 植物装扮字典[code]
            elif code in 道具字典:
                item_name = 道具字典[code]
            else:
                item_name = f"未知物品 ({code})"
            print(f"  {item_name} (代码: {code}) 数量: {quantity}, 概率: {probability}")
    else:
        print("未发现罐子奖励信息。")
    gl_list = inner_data.get("gl", [])
    if gl_list:
        print("已获得奖励代码：", end=" ")
        for code in gl_list:
            code = str(code)
            if code in 植物字典:
                name = 植物字典[code]
            elif code in 植物装扮字典:
                name = 植物装扮字典[code]
            elif code in 道具字典:
                name = 道具字典[code]
            else:
                name = f"未知({code})"
            print(f"{name}({code})", end="  ")
        print()
    else:
        print("未获得任何奖励代码。")
    reset_choice = input("是否重置砸罐子？(Y/N): ").strip().lower()
    if reset_choice == "y":
        data_reset = {"req": "V919","e": {"f": "0","pi": pi,"sk": sk,"ui": ui},"ev": 1}
        success_reset, reset_response = send_加密发送_解密响应(data_reset)
        if not success_reset:
            print("砸罐子重置请求失败！")
        else:
            print("【砸罐子重置结果】")
            bl_list = reset_response.get("bl", [])
            if bl_list:
                print("重置后奖励列表：")
                for item in bl_list:
                    code = str(item.get("i", ""))
                    quantity = item.get("q", 0)
                    probability = item.get("w", "N/A")
                    if code in 植物字典:
                        item_name = 植物字典[code]
                    elif code in 植物装扮字典:
                        item_name = 植物装扮字典[code]
                    elif code in 道具字典:
                        item_name = 道具字典[code]
                    else:
                        item_name = f"未知物品 ({code})"
                    print(f"  {item_name} (代码: {code}) 数量: {quantity}, 概率: {probability}")
            else:
                print("未收到重置后奖励信息。")
            rn = reset_response.get("rn")
            if rn is not None:
                print(f"重置后抽奖次数: {rn}")
            lh_reset = reset_response.get("lh")
            if lh_reset is not None:
                print(f"重置后剩余锤子数量: {lh_reset}")
            print("-" * 50)
    else:
        print("未选择重置。")
    can_position = input("请输入要砸的罐子位置: ").strip()
    if not can_position:
        print("未输入罐子位置，结束砸罐子流程。")
        return
    data_smash = {"req": "V918","e": {"i": can_position,"pi": pi,"sk": sk,"ui": ui},"ev": 1}
    success_smash, smash_response = send_加密发送_解密响应(data_smash)
    if not success_smash:
        print("砸罐子请求失败！")
        return
    print("【砸罐子结果】")
    b_field = smash_response.get("b", {})
    if b_field:
        code = str(b_field.get("i", ""))
        quantity = b_field.get("q", 0)
        probability = b_field.get("w", "N/A")
        if code in 植物字典:
            item_name = 植物字典[code]
        elif code in 植物装扮字典:
            item_name = 植物装扮字典[code]
        elif code in 道具字典:
            item_name = 道具字典[code]
        else:
            item_name = f"未知物品 ({code})"
        print(f"砸罐子获得: {item_name} (代码: {code}) 数量: {quantity}, 概率: {probability}")
    else:
        print("砸罐子未获得奖励。")
    lh = smash_response.get("lh")
    if lh is not None:
        print(f"剩余锤子数量: {lh}")
    
def make_收取同游币():
    data = {"req":"V303","e":{"al":[{"id":10892,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    info = json.loads(decrypted_json[0]["data"])
    
    print("【同游币信息】")
    invCode = info.get("invCode")
    tokenCurCnt = info.get("tokenCurCnt")
    itemNum = info.get("itemNum")
    print(f"邀请码: {invCode}")
    print(f"总同游币: {tokenCurCnt}")
    print(f"我的同游币: {itemNum}")
    memberList = info.get("memberList", [])
    if memberList:
        print("团队成员:")
        for idx, member_info in enumerate(memberList, start=1):
            member = member_info.get("member", {})
            mpi = member.get("pi")
            name = member.get("n") 
            tokenCnt = member_info.get("tokenCnt", 0)
            isLeader = member_info.get("isLeader", False)
            leader_flag = "【队长】" if isLeader else ""
            print(f"{idx}. {name}{leader_flag} (mpi: {mpi}) - 可收取同游币: {tokenCnt}")
    else:
        print("没有团队成员信息。")
        return
    choice = input("请输入要收取同游币的队员序号（直接回车跳过收取）: ").strip()
    if not choice:
        print("跳过同游币收取。")
        return
    try:
        choice_index = int(choice)
    except Exception as e:
        print("输入错误，终止操作。")
        return
    if choice_index < 1 or choice_index > len(memberList):
        print("序号超出范围，终止操作。")
        return
    selected_member_info = memberList[choice_index - 1]
    selected_member = selected_member_info.get("member", {})
    selected_mpi = selected_member.get("pi")
    tc = str(selected_member_info.get("tokenCnt", 0))
    print(f"将自动收取该成员可收取的同游币: {tc}")
    data_collect = {
        "req": "V1050",
        "e": {
            "mpi": str(selected_mpi),
            "pi": pi,
            "sk": sk,
            "tc": tc,
            "ui": ui
        },
        "ev": 1
    }
    _, collect_response = send_加密发送_解密响应(data_collect)
    print("【收取同游币响应】")
    print(json.dumps(collect_response, indent=2, ensure_ascii=False))

def make_团购():
    data = {"req":"V303","e":{"al":[{"id":10728,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(data, "进入团购商店")
    _, decrypted_json = send_加密发送_解密响应(data)
    inner_data = json.loads(decrypted_json[0]["data"])
    il_list = inner_data.get("il", [])
    if not il_list:
        print("团购商品列表为空。")
        return
    currency_dict = {
        "3010": "戴夫券",
        "3008": "钻石"
    }
    
    print("【团购商品列表】")
    for idx, item in enumerate(il_list, start=1):
        code = str(item.get("i"))
        q = item.get("q")
        c = item.get("c")
        d = item.get("d")
        needItem = str(item.get("needItem"))
        
        if code in 植物字典:
            name = 植物字典[code]
            type_desc = "阶数"
        elif code in 植物装扮碎片字典:
            name = 植物装扮碎片字典[code]
            type_desc = "数量"
        elif code in 道具字典:
            name = 道具字典[code]
            type_desc = "数量"
        else:
            name = f"未知商品 ({code})"
            type_desc = "数量"
        if needItem == "3010":
            d_desc = f"可购买数量: {d}"
        else:
            d_desc = f"折数: {d}"
        currency_name = currency_dict.get(needItem, f"未知货币({needItem})")
        
        print(f"{idx}. {name} - {type_desc}: {q}, 花费: {c}, {d_desc}, 货币: {currency_name}")
    
    choice = input("请选择要购买的商品编号: ").strip()
    try:
        choice_index = int(choice)
    except Exception as e:
        print("输入错误，结束团购操作。")
        return
    if choice_index < 1 or choice_index > len(il_list):
        print("编号超出范围，结束操作。")
        return
    selected = il_list[choice_index - 1]
    gi = str(selected.get("i"))
    q_val = str(selected.get("q"))
    ci_cost = str(selected.get("c"))
    needItem_code = str(selected.get("needItem"))
    si_val = "3"
    
    data_purchase = {
        "req": "V392",
        "e": {
            "ci": ci_cost,
            "gi": gi,
            "mi": needItem_code,
            "pi": pi,
            "q": q_val,
            "si": si_val,
            "sk": sk,
            "ui": ui
        },
        "ev": 1
    }
    _, purchase_response = send_加密发送_解密响应(data_purchase)
    print("【团购购买响应】")
    print(json.dumps(purchase_response, indent=2, ensure_ascii=False))

def make_激活新人活动():
    活动字典 = {
        "10875": "七天签到",
        "10828": "七天指南",
        "10876": "新人商店",
        "10843": "潘妮课堂",
        "10877": "充钱活动"
    }
    data = {"req":"V303","e":{"al":[{"id":10874,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        inner_data = json.loads(decrypted_json[0]["data"])
    except Exception as e:
        print("解析响应数据失败：", e)
        return

    print("【激活新人活动】")
    al_list = inner_data.get("al", [])
    if not al_list:
        print("没有新人活动信息。")
        return

    for item in al_list:
        i_val = str(item.get("i"))
        o_val = item.get("o")
        activity_name = 活动字典.get(i_val, "未知活动")
        print(f"活动 i: {i_val} ({activity_name}), o: {o_val}")

def make_新人七天签到():
    make_激活新人活动()
    data = {"req":"V303","e":{"al":[{"id":10875,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        inner_data = json.loads(decrypted_json[0]["data"])
    except Exception as e:
        print("解析响应数据失败：", e)
        return
    gift_list = inner_data.get("gift_list", [])
    sign_days = inner_data.get("sign_days", "0")
    print("【新人七天签到】")
    print(f"当前签到天数: {sign_days}")
    if not gift_list:
        print("签到礼物列表为空。")
    else:
        print("签到礼物列表：")
        for gift in gift_list:
            code = str(gift.get("i"))
            quantity = gift.get("q")
            status = gift.get("s")
            if code in 道具字典:
                item_name = 道具字典[code]
            elif code in 植物装扮字典:
                item_name = 植物装扮字典[code]
            elif code in 植物字典:
                item_name = 植物字典[code]
            else:
                item_name = f"未知物品 ({code})"
            received = "已领取" if status == 1 else "未领取"
            print(f"物品: {item_name} 数量: {quantity} - {received}")
    data_sign = {
        "req": "V998",
        "e": {
            "pi": pi,
            "sk": sk,
            "ui": ui
        },
        "ev": 1
    }
    _, sign_response = send_加密发送_解密响应(data_sign)
    print("【签到请求响应】")
    print(json.dumps(sign_response, indent=2, ensure_ascii=False))

def make_七天指南详情():
    make_激活新人活动()
    data = {"req":"V303","e":{"al":[{"id":10828,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        inner_data = json.loads(decrypted_json[0]["data"])
    except Exception as e:
        print("解析响应数据失败：", e)
        return

    try:
        details = json.loads(inner_data.get("data", "{}"))
    except Exception as e:
        print("解析详情数据失败：", e)
        return

    print("【七天指南详情】")
    black_list = details.get("black_list", [])
    print("black_list:", black_list)
    stage_bonus_list = details.get("stage_bonus", [])
    for bonus in stage_bonus_list:
        bl_items = bonus.get("bl", [])
        for gift in bl_items:
            code = str(gift.get("i"))
            quantity = gift.get("q")
            if code in 植物碎片字典:
                item_name = 植物碎片字典[code]
            elif code in 道具字典:
                item_name = 道具字典[code]
            elif code in 植物装扮碎片字典:
                item_name = 植物装扮碎片字典[code]
            else:
                item_name = f"未知({code})"
            print(f"物品: {item_name}, 数量: {quantity}")

def make_新人商店():
    make_激活新人活动()
    data = {"req":"V303","e":{"al":[{"id":10876,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    try:
        inner_data = json.loads(decrypted_json[0]["data"])
    except Exception as e:
        print("解析响应数据失败:", e)
        return
    try:
        details = json.loads(inner_data.get("data", "{}"))
    except Exception as e:
        print("解析详情数据失败:", e)
        return
    bl = details.get("bl", [])
    if not bl:
        print("新人商店商品列表为空。")
        return
    print("【新人商店商品列表】")
    for idx, sublist in enumerate(bl, start=1):
        if not sublist:
            continue
        product = sublist[0]
        code = str(product.get("i"))
        q = product.get("q")
        condition = product.get("condition")
        limitation = product.get("limitation")
        if code in 植物碎片字典:
            name = 植物碎片字典[code]
        elif code in 道具字典:
            name = 道具字典[code]
        elif code in 植物装扮碎片字典:
            name = 植物装扮碎片字典[code]
        else:
            name = f"未知商品 ({code})"
        print(f"{idx}. 商品: {name} - 数量: {q}, 价格: {condition}, 限购: {limitation}")
    
    choice = input("请选择要购买的商品编号: ").strip()
    if not choice:
        print("未选择商品，退出购买。")
        return
    try:
        choice_index = int(choice)
    except Exception as e:
        print("输入错误，退出购买。")
        return
    if choice_index < 1 or choice_index > len(bl):
        print("选择编号超出范围。")
        return
    purchase_id = str(choice_index - 1)
    
    data_purchase = {
        "req": "V1008",
        "e": {
            "id": purchase_id,
            "pi": pi,
            "sk": sk,
            "ui": ui
        },
        "ev": 1
    }
    _, purchase_response = send_加密发送_解密响应(data_purchase)
    print("【购买响应】")
    print(json.dumps(purchase_response, indent=2, ensure_ascii=False))

def make_进入追击():
    data1 = {"req":"V303","e":{"al":[{"id":10800,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(data1, "进入追击1")
    data2 = {"req":"V303","e":{"al":[{"id":10829,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(data2, "进入追击2")
    data3 = {"req":"V303","e":{"al":[{"id":10615,"abi":0,"type":1,"config_version":1}],"ci":"93","cs":"0","pack":"com.popcap.pvz2cthdbk","pi":pi,"rv":"5","sk":sk,"ui":ui,"v":newest_version},"ev":1}
    send_加密发送_拼接提示(data3, "进入追击3")

def make_追击商店购买():
    make_进入追击()
    def refresh_shop():
        refresh_requests = [
            {"req": "V928", "e": {"ad": "0", "c": "0", "is": "0", "pi": pi, "s": "0", "sk": sk, "ui": ui}, "ev": 1},
            {"req": "V928", "e": {"ad": "1", "c": "0", "is": "0", "pi": pi, "s": "0", "sk": sk, "ui": ui}, "ev": 1},
            {"req": "V928", "e": {"ad": "0", "c": "0", "is": "0", "pi": pi, "s": "1", "sk": sk, "ui": ui}, "ev": 1}
        ]
        for req in refresh_requests:
            _, resp = send_加密发送_解密响应(req)
            if not resp:
                print("刷新响应为空:", resp)
                continue
            if isinstance(resp, list):
                resp_str = resp[0]
            elif isinstance(resp, str):
                resp_str = resp
            elif isinstance(resp, dict):
                resp_str = json.dumps(resp, ensure_ascii=False)
            else:
                resp_str = str(resp)

            if resp_str == "0":
                print("刷新响应无效:", resp)
                continue
            try:
                shop_data = json.loads(resp_str)
                if "si" in shop_data and shop_data["si"]:
                    return shop_data
            except Exception as e:
                print("解析刷新响应失败:", e)
        return None

    shop = refresh_shop()
    if not shop:
        print("所有刷新方式均失败，退出函数。")
        return
    shop_list = shop.get("si", [])
    processed_items = []
    for item in shop_list:
        new_item = item.copy()
        new_item["oi"] = str(item.get("oi"))
        processed_items.append(new_item)

    ag = shop.get("ag", 0)
    print("剩余追击币:", ag)
    print("【当前商店商品列表】")
    for idx, item in enumerate(processed_items, start=1):
        code = item.get("oi")
        q_val = item.get("q")
        price = item.get("p")
        l_flag = item.get("l")  
        purchasable = "可购" if str(l_flag) == "1" else "不可购"
        if code in 植物碎片字典:
            name = 植物碎片字典[code]
        elif code in 道具字典:
            name = 道具字典[code]
        elif code in 植物装扮碎片字典:
            name = 植物装扮碎片字典[code]
        else:
            name = f"未知({code})"
        print(f"{idx}. 商品: {name} - 数量: {q_val}, 价格: {price}, {purchasable}")

    mode = input("请选择购买模式：自动(1) 或 手动(2)：").strip().upper()
    if mode == "1":
        rounds_input = input("请输入自动购买轮数（刷新次数）：").strip()
        try:
            rounds = int(rounds_input)
        except:
            print("输入轮数错误，退出。")
            return
        for r in range(1, rounds + 1):
            desc = input(f"【自动购买第{r}轮】请输入本轮要购买的目标商品代码（用空格分隔）：").strip()
            if not desc:
                print("未输入目标代码，本轮跳过。")
            else:
                target_codes = desc.split()
                for target in target_codes:
                    if target == "23113":
                        candidates = [it for it in processed_items if it.get("oi") in {"23113", "23116", "23117"} and str(it.get("l")) == "1"]
                    elif target == "23112":
                        candidates = [it for it in processed_items if it.get("oi") in {"23112", "23114", "23115"} and str(it.get("l")) == "1"]
                    else:
                        candidates = [it for it in processed_items if it.get("oi") == target and str(it.get("l")) == "1"]
                    if not candidates:
                        print(f"目标 {target} 在当前商店暂不可购。")
                        continue
                    chosen = min(candidates, key=lambda x: x.get("p", 10**9))
                    purchase_data = {
                        "req": "V392",
                        "e": {
                            "ci": str(chosen.get("p")),
                            "gi": str(chosen.get("oi")),  
                            "mi": "23093",
                            "pi": pi,
                            "q": str(chosen.get("q")),   
                            "si": "8",                   
                            "sk": sk,
                            "ui": ui
                        },
                        "ev": 1
                    }
                    _, resp_purchase = send_加密发送_解密响应(purchase_data)
                    print(f"自动购买目标 {target} 购买响应：", json.dumps(resp_purchase, indent=2, ensure_ascii=False))
            if r != rounds:
                print("自动刷新商店……")
                shop = refresh_shop()
                if not shop:
                    print("刷新失败，退出自动购买。")
                    return
                shop_list = shop.get("si", [])
                processed_items = []
                for item in shop_list:
                    new_item = item.copy()
                    new_item["oi"] = str(item.get("oi"))
                    processed_items.append(new_item)
                print("刷新后剩余追击币:", shop.get("ag", 0))
    elif mode == "2":
        while True:
            print("【手动购买模式】")
            for idx, item in enumerate(processed_items, start=1):
                code = item.get("oi")
                q_val = item.get("q")
                price = item.get("p")
                l_flag = item.get("l")
                purchasable = "可购" if str(l_flag) == "1" else "不可购"
                if code in 植物碎片字典:
                    name = 植物碎片字典[code]
                elif code in 道具字典:
                    name = 道具字典[code]
                elif code in 植物装扮碎片字典:
                    name = 植物装扮碎片字典[code]
                else:
                    name = f"未知({code})"
                print(f"{idx}. 商品: {name} - 数量: {q_val}, 价格: {price}, {purchasable}")
            choice = input("请输入要购买的商品序号（留空退出）：").strip()
            if not choice:
                print("退出手动购买。")
                break
            try:
                idx_choice = int(choice)
            except:
                print("输入错误。")
                continue
            if idx_choice < 1 or idx_choice > len(processed_items):
                print("序号超出范围。")
                continue
            chosen = processed_items[idx_choice - 1]
            if str(chosen.get("l")) != "1":
                print("该商品不可购买。")
                continue
            purchase_data = {
                "req": "V392",
                "e": {
                    "ci": str(chosen.get("p")),
                    "gi": str(chosen.get("oi")),
                    "mi": "23093",
                    "pi": pi,
                    "q": str(chosen.get("q")),
                    "si": "8",
                    "sk": sk,
                    "ui": ui
                },
                "ev": 1
            }
            _, resp_purchase = send_加密发送_解密响应(purchase_data)
            print("购买响应：", json.dumps(resp_purchase, indent=2, ensure_ascii=False))
            refresh_opt = input("是否刷新商店？(1)：").strip().upper()
            if refresh_opt == "1":
                shop = refresh_shop()
                if not shop:
                    print("刷新失败。")
                    break
                shop_list = shop.get("si", [])
                processed_items = []
                for item in shop_list:
                    new_item = item.copy()
                    new_item["oi"] = str(item.get("oi"))
                    processed_items.append(new_item)
                print("刷新后剩余追击币:", shop.get("ag", 0))
    else:
        print("未选择正确的购买模式。")
    
def make_令营领取():
    data = {"req":"V1105","e":{"pi":pi,"sk":sk,"ui":ui},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    reward_list = decrypted_json.get("reward_list", [])
    for reward in reward_list:
        i_val = str(reward.get("i"))
        q = reward.get("q")
        if i_val in 道具字典:
            name = 道具字典[i_val]
        elif i_val in 植物碎片字典:
            name = 植物碎片字典[i_val]
        elif i_val in 植物装扮碎片字典:
            name = 植物装扮碎片字典[i_val]
        else:
            name = "未知物品"
        print("获得奖励: {} 数量: {}".format(name, q))

def make_双人领取():
    data = {"req":"V1100","e":{"pi":pi,"sk":sk,"ui":ui},"ev":1}
    _, decrypted_json = send_加密发送_解密响应(data)
    reward_list = decrypted_json.get("reward_list", [])
    for reward in reward_list:
        i_val = str(reward.get("i"))
        q = reward.get("q")
        if i_val in 道具字典:
            name = 道具字典[i_val]
        elif i_val in 植物碎片字典:
            name = 植物碎片字典[i_val]
        elif i_val in 植物装扮碎片字典:
            name = 植物装扮碎片字典[i_val]
        else:
            name = "未知物品"
        print("获得奖励: {} 数量: {}".format(name, q))

def make_令营抽奖():
    total_rewards = {} 
    config_data = {"req": "V303", "e": {"al": [{"id":10851, "abi":0, "type":1, "config_version":1}],
                                         "ci":"93", "cs":"0", "pack":"com.popcap.pvz2cthdbk",
                                         "pi":pi, "rv":"5", "sk":sk, "ui":ui, "v":newest_version},
                   "ev":1}
    success, config_response = send_加密发送_解密响应(config_data)
    if not success:
        print("获取抽奖配置失败")
        return
    box_configs = {}
    try:
        if isinstance(config_response, list) and len(config_response) > 0:
            data_str = config_response[0].get("data", "{}")
            data = json.loads(data_str)
            if "rrbl" in data:
                for item in data["rrbl"]:
                    if "boxId" in item and "boxList" in item:
                        box_id = item["boxId"]
                        box_list = item["boxList"]
                        box_configs[box_id] = box_list                        
        print(f"已加载 {len(box_configs)} 个自选奖励配置")
    except Exception as e:
        print(f"解析配置信息失败: {e}")
        return

    for ln in range(12):
        print(f"第 {ln + 1} 次抽奖...")
        data = {"req":"V430","e":{"ln":str(ln),"pi":pi,"sk":sk,"type":"0","ui":ui},"ev":1}
        success, decrypted_json = send_加密发送_解密响应(data)
        if not success:
            print(f"第 {ln + 1} 次抽奖失败")
            continue
            
        awardIndex = decrypted_json.get("awardIndex")
        
        if "reward_list" in decrypted_json:
            reward_list = decrypted_json["reward_list"]
            print(f"获得奖励:")
            for reward in reward_list:
                item_id = str(reward.get("i"))
                quantity = reward.get("q", 1)
                item_name = "未知物品"
                if item_id in 道具字典:
                    item_name = 道具字典[item_id]
                elif item_id in 植物碎片字典:
                    item_name = 植物碎片字典[item_id]
                else:
                    item_name = f"未知物品({item_id})"
                print(f"  - {item_name} x{quantity}")
                total_rewards[item_name] = total_rewards.get(item_name, 0) + quantity
        elif awardIndex is not None:
            print(f"需要自选奖励，awardIndex: {awardIndex}")
            if awardIndex in box_configs:
                box_list = box_configs[awardIndex]
                print("可选择的奖励:")
                for idx, option in enumerate(box_list):
                    item_id = str(option.get("i"))
                    quantity = option.get("q", 1)
                    item_name = "未知物品"
                    if item_id in 道具字典:
                        item_name = 道具字典[item_id]
                    elif item_id in 植物碎片字典:
                        item_name = 植物碎片字典[item_id]
                    else:
                        item_name = f"未知物品({item_id})"
                    print(f"  {idx}: {item_name} x{quantity}")
                while True:
                    try:
                        choice = input(f"请选择奖励 (0-{len(box_list)-1}): ").strip()
                        bai = int(choice)
                        if 0 <= bai < len(box_list):
                            break
                        else:
                            print(f"请输入 0 到 {len(box_list)-1} 之间的数字！")
                    except ValueError:
                        print("请输入有效的数字！")
            else:
                print(f"未找到awardIndex {awardIndex}对应的选项配置")
                while True:
                    try:
                        bai = input("请输入选择位置 (0-其他数字): ").strip()
                        int(bai)
                        break
                    except ValueError:
                        print("请输入有效的数字！")
            
            select_data = {
                "req": "V430",
                "e": {
                    "bai": str(bai),
                    "gi": str(awardIndex),
                    "pi": pi,
                    "sk": sk,
                    "type": "1",
                    "ui": ui
                },
                "ev": 1
            }
            
            select_success, select_response = send_加密发送_解密响应(select_data)
            if select_success:
                print(f"自选奖励成功，选择位置: {bai}")
                if "reward_list" in select_response:
                    reward_list = select_response["reward_list"]
                    print(f"获得奖励:")
                    for reward in reward_list:
                        item_id = str(reward.get("i"))
                        quantity = reward.get("q", 1)
                        item_name = "未知物品"
                        if item_id in 道具字典:
                            item_name = 道具字典[item_id]
                        elif item_id in 植物碎片字典:
                            item_name = 植物碎片字典[item_id]
                        else:
                            item_name = f"未知物品({item_id})"
                        print(f"  - {item_name} x{quantity}")
                        total_rewards[item_name] = total_rewards.get(item_name, 0) + quantity
            else:
                print(f"自选奖励失败")
        else:
            print(f"第 {ln + 1} 次抽奖失败")
            
    print("令营抽奖完成！")
    print("累计获得奖励：")
    if total_rewards:
        for reward, qty in total_rewards.items():
            print(f"{reward} x{qty}")
    else:
        print("未获得任何奖励")
def make_双人抽奖():
    total_rewards = {} 
    config_data = {"req": "V303", "e": {"al": [{"id":10861, "abi":0, "type":1, "config_version":1}],
                                         "ci":"93", "cs":"0", "pack":"com.popcap.pvz2cthdbk",
                                         "pi":pi, "rv":"5", "sk":sk, "ui":ui, "v":newest_version},
                   "ev":1}
    success, config_response = send_加密发送_解密响应(config_data)
    if not success:
        print("获取双人抽奖配置失败")
        return
    box_configs = {}
    try:
        if isinstance(config_response, list) and len(config_response) > 0:
            data_str = config_response[0].get("data", "{}")
            data = json.loads(data_str)
            if "rrbl" in data:
                for item in data["rrbl"]:
                    if "boxId" in item and "boxList" in item:
                        box_id = item["boxId"]
                        box_list = item["boxList"]
                        box_configs[box_id] = box_list                        
        print(f"已加载 {len(box_configs)} 个自选奖励配置")
    except Exception as e:
        print(f"解析配置信息失败: {e}")
        return

    for ln in range(12):
        print(f"第 {ln + 1} 次双人抽奖...")
        data = {"req": "V855", "e": {"ln": str(ln), "pi": pi, "sk": sk, "type": "0", "ui": ui}, "ev": 1}
        success, decrypted_json = send_加密发送_解密响应(data)
        if not success:
            print(f"第 {ln + 1} 次抽奖失败")
            continue          
        awardIndex = decrypted_json.get("awardIndex")
        if "reward_list" in decrypted_json:
            reward_list = decrypted_json["reward_list"]
            print(f"获得奖励:")
            for reward in reward_list:
                item_id = str(reward.get("i"))
                quantity = reward.get("q", 1)
                item_name = "未知物品"
                if item_id in 道具字典:
                    item_name = 道具字典[item_id]
                elif item_id in 植物碎片字典:
                    item_name = 植物碎片字典[item_id]
                elif item_id in 植物字典:
                    item_name = 植物字典[item_id]
                elif item_id in 植物装扮字典:
                    item_name = 植物装扮字典[item_id]
                if item_name == "未知物品":
                    print(f"  - {item_name}(ID:{item_id}) x{quantity}")
                else:
                    print(f"  - {item_name} x{quantity}")
                total_rewards[item_name] = total_rewards.get(item_name, 0) + quantity
        elif awardIndex is not None:
            print(f"需要自选奖励，awardIndex: {awardIndex}")
            if awardIndex in box_configs:
                box_list = box_configs[awardIndex]
                print("可选择的奖励:")
                for idx, option in enumerate(box_list):
                    item_id = str(option.get("i"))
                    quantity = option.get("q", 1)
                    item_name = "未知物品"
                    if item_id in 植物碎片字典:
                        item_name = 植物碎片字典[item_id]
                    elif item_id in 植物字典:
                        item_name = 植物字典[item_id]
                    elif item_id in 植物装扮字典:
                        item_name = 植物装扮字典[item_id]
                    if item_name == "未知物品":
                        print(f"  {idx}: {item_name}(ID:{item_id}) x{quantity}")
                    else:
                        print(f"  {idx}: {item_name} x{quantity}")
                while True:
                    try:
                        choice = input(f"请选择奖励 (0-{len(box_list)-1}): ").strip()
                        bai = int(choice)
                        if 0 <= bai < len(box_list):
                            break
                        else:
                            print(f"请输入 0 到 {len(box_list)-1} 之间的数字！")
                    except ValueError:
                        print("请输入有效的数字！")
            else:
                print(f"未找到awardIndex {awardIndex}对应的选项配置")
                while True:
                    try:
                        bai = input("请输入选择位置 (0-其他数字): ").strip()
                        bai = int(bai)
                        break
                    except ValueError:
                        print("请输入有效的数字！")
            select_data = {
                "req": "V855",
                "e": {
                    "bai": str(bai),
                    "gi": str(awardIndex),
                    "pi": pi,
                    "sk": sk,
                    "type": "1",
                    "ui": ui
                },
                "ev": 1
            }
            select_success, select_response = send_加密发送_解密响应(select_data)
            if select_success:
                print(f"自选奖励成功，选择位置: {bai}")
                if "reward_list" in select_response:
                    reward_list = select_response["reward_list"]
                    print(f"获得奖励:")
                    for reward in reward_list:
                        item_id = str(reward.get("i"))
                        quantity = reward.get("q", 1)
                        item_name = "未知物品"
                        if item_id in 道具字典:
                            item_name = 道具字典[item_id]
                        elif item_id in 植物碎片字典:
                            item_name = 植物碎片字典[item_id]
                        elif item_id in 植物字典:
                            item_name = 植物字典[item_id]
                        elif item_id in 植物装扮字典:
                            item_name = 植物装扮字典[item_id]
                        if item_name == "未知物品":
                            print(f"  - {item_name}(ID:{item_id}) x{quantity}")
                        else:
                            print(f"  - {item_name} x{quantity}")
                        total_rewards[item_name] = total_rewards.get(item_name, 0) + quantity
            else:
                print(f"自选奖励失败")
        else:
            print(f"第 {ln + 1} 次抽奖失败")
            
    print("双人抽奖完成！")
    print("累计获得奖励：")
    if total_rewards:
        for reward, qty in total_rewards.items():
            print(f"{reward} x{qty}")
    else:
        print("未获得任何奖励")
def make_无尽榜单():
    mode = input("请选择查询类型 (1：查询榜单  2：查询自己信息): ").strip()
    mapping = {"1": 0, "2": 20, "3": 40, "4": 60, "5": 80}
    if mode == "1":
        seg = input("请选择榜单段位:\n"
                    "1：1-20\n"
                    "2：21-40\n"
                    "3：41-60\n"
                    "4：61-80\n"
                    "5：81-100\n"
                    "6：前100全部显示\n"
                    "请输入选项：").strip()
        if seg == "6":
            all_items = []
            my_level = None
            my_er = None
            for key in ["1", "2", "3", "4", "5"]:
                of_val = mapping.get(key)
                data = {
                    "req": "V222",
                    "e": {
                        "p": {"of": of_val},
                        "pi": pi, 
                        "rv": "5",
                        "sk": sk,
                        "t": "12",
                        "ui": ui
                    },
                    "ev": 1
                }
                _, decrypted_json = send_加密发送_解密响应(data)
                if "j" not in decrypted_json:
                    print("无尽关闭")
                    return
                result = json.loads(decrypted_json["j"])
                if my_level is None:
                    my_level = result.get("l")
                    my_er = result.get("er", {})
                all_items.extend(result.get("ell", []))
            print("\n========================")
            print("关卡：", my_level)
            print("自己排名：", (my_er.get("r", 0) + 1), "分数：", my_er.get("s"))
            print("榜单：")
            for item in all_items:
                print("排名：", (item.get("r", 0) + 1), "名字：", item.get("n"), "分数：", item.get("s"))
        else:
            of_val = mapping.get(seg)
            if of_val is None:
                print("无效的输入")
                return
            data = {
                "req": "V222",
                "e": {
                    "p": {"of": of_val},
                    "pi": pi,
                    "rv": "5",
                    "sk": sk,
                    "t": "12",
                    "ui": ui
                },
                "ev": 1
            }
            _, decrypted_json = send_加密发送_解密响应(data)
            if "j" not in decrypted_json:
                print("无尽关闭")
                return
            result = json.loads(decrypted_json["j"])
            print("\n========================")
            print("关卡：", result.get("l"))
            er = result.get("er", {})
            print("自己排名：", (er.get("r", 0) + 1), "分数：", er.get("s"))
            print("榜单：")
            for item in result.get("ell", []):
                print("排名：", (item.get("r", 0) + 1), "名字：", item.get("n"), "分数：", item.get("s"))
    elif mode == "2":
        data = {
            "req": "V222",
            "e": {
                "p": {"of": 0},
                "pi": pi,
                "rv": "5",
                "sk": sk,
                "t": "12",
                "ui": ui
            },
            "ev": 1
        }
        _, decrypted_json = send_加密发送_解密响应(data)
        if "j" not in decrypted_json:
            print("无尽关闭")
            return
        result = json.loads(decrypted_json["j"])
        print("\n========================")
        print("关卡：", result.get("l"))
        er = result.get("er", {})
        print("自己排名：", (er.get("r", 0) + 1), "分数：", er.get("s"))
    else:
        print("无效的选择")

def make_邮箱():
    data = {"req":"V310","e":{"a":"15","em":"466797675@qq.com","p":"13767997888","pi":pi,"s":"0","sk":sk,"ui":ui},"ev":1}
    send_加密发送_拼接提示(data, "邮箱绑定")
def make_兑换码():
    user_code = input("请输入兑换码：").strip()
    data = {
        "req": "V330",
        "e": {
            "c": user_code,
            "ch": "com.popcap.pvz2cthdbk",
            "pi": pi,   
            "sk": sk,
            "ui": ui
        },
        "ev": 1
    }
    
    success, response = send_加密发送_解密响应(data)
    if not success:
        print("兑换码请求失败")
        return
    msg = response.get("msg", "")
    print(msg)
    reward_list = response.get("g", [])
    for reward in reward_list:
        item_id = str(reward.get("i"))
        quantity = reward.get("q", 1)
        item_name = "未知物品"
        if item_id in 植物碎片字典:
            item_name = 植物碎片字典[item_id]
        elif item_id in 道具字典:
            item_name = 道具字典[item_id]
        elif item_id in 植物装扮碎片字典:
            item_name = 植物装扮碎片字典[item_id]
        
        if item_name == "未知物品":
            print(f"  - {item_name}(ID:{item_id}) x{quantity}")
        else:
            print(f"  - {item_name} x{quantity}")
    p_info = response.get("p", {})
    g1 = p_info.get("g1")
    if g1 is not None:
        print(f"钻石数量： {g1}")

def make_版本更新():
    渠道信息 = requests.post(tw_url)
    渠道信息_data = json.loads(渠道信息.text)
    print(f"上一次刷新时间为 {渠道信息_data['queryDateTime']}")
    for item in 渠道信息_data["latestVersions"]:
        item["渠道"] = item.pop("qudao")
        item["最新版本"] = item.pop("version")
        item.pop("status", None)
        print(f"渠道:  {item['渠道']},  最新版本:  {item['最新版本']}")

def make_查双人僵尸():
    data = {"req": "V303","e": {"al": [{"id": 10859, "abi": 0, "type": 1, "config_version": 1}],"ci": "93","cs": "0","pack": "com.popcap.pvz2cthdbk","pi": pi,"rv": "5","sk": sk,"ui": ui,"v": newest_version},"ev": 1}
    success, response = send_加密发送_解密响应(data)
    if not success:
        print("请求失败，返回:", response)
        return None
    try:
        if not isinstance(response, list) or len(response) == 0:
            print("响应格式错误：预期为非空列表")
            return None
        resp_dict = response[0]
        data_str = resp_dict.get("data")
        if not data_str:
            print("响应中未找到 data 字段")
            return None
        parsed = json.loads(data_str)
    except Exception as e:
        print(f"解析 data 字段出错: {e}")
        return None
    zombies_data = parsed.get("zombiesData")
    if not zombies_data:
        print("未找到 zombiesData 字段")
        return None
    zombie_list = zombies_data.get("list", [])
    chip_list   = zombies_data.get("chip", [])
    
    print("----- 已激活僵尸 -----")
    activated_strings = []
    activated_info = [] 
    if zombie_list:
        for item in zombie_list:
            try:
                code = item.get("i")
                lv = int(item.get("lv", 0))
                if code is None:
                    continue
                upgrade_id = int(code) + 4000
                zombie_name = 双人对决僵尸字典.get(str(upgrade_id))
                if not zombie_name:
                    zombie_name = str(code)
                activated_strings.append(f"{zombie_name} (等级: {lv})")
                activated_info.append({"name": zombie_name, "lv": lv, "base_id": int(code)})
            except Exception as exc:
                print(f"解析激活僵尸时出错: {exc}")
    else:
        print("没有激活的僵尸")
    if activated_strings:
        print_grouped(activated_strings, 2, col_width=25)
    
    print("----- 僵尸碎片 -----")
    fragments_strings = []
    fragments_dict = {}
    if chip_list:
        for chip in chip_list:
            try:
                chip_code = chip.get("i")
                qty = int(chip.get("q", 0))
                if chip_code is None:
                    continue
                chip_name = 双人对决僵尸字典.get(str(chip_code))
                if not chip_name:
                    chip_name = str(chip_code)
                fragments_strings.append(f"{chip_name}: 数量 {qty}")
                fragments_dict[str(chip_code)] = qty
            except Exception as exp:
                print(f"解析僵尸碎片时出错: {exp}")
    else:
        print("没有僵尸碎片")
    if fragments_strings:
        print_grouped(fragments_strings, 2, col_width=25)
    return activated_info, fragments_dict

def make_ukugd():
    global uk
    data = {"req": "V316", "e": {"b": "0", "n": "", "pi": pi, "sk": sk, "ui": ui}, "ev": 1}
    success, response = send_加密发送_解密响应(data)
    if success and response:
        try:
            new_uk = response.get("p", {}).get("uk")
            if new_uk:
                uk = new_uk
                print("uk已更新为:", uk)
            else:
                print("响应中未找到uk")
        except Exception as e:
            print(f"解析uk出错: {e}")
    else:
        print("请求失败，无法更新uk")






def display_menu():
    title = "《Android》"
    print(f"\033[1;36m{title.center(30)}\033[0m")
    print("=" * 30)
    menu_items = {
        "0": "官服改密",
        "1": "日常", "2": "探险",
        "3": "双人", "4": "令营",
        "5": "砸罐", "6": "回忆之旅",
        "7": "创意庭院", "8": "追击",
        "9": "秘境", "10": "秘宝",
        "11": "无尽", "12": "时空寻宝",
        "13": "免费神器", "14": "挂件",
        "15": "超Z", "16": "主线钻石",
        "17": "问卷", "18": "兑换码",
        "19": "邮箱", "20": "新人",
        "21": "僵博", "22": "同游",
        "23": "原木", "24": "响叮当",
        "25": "转基因", "26": "家族",
        "27": "趣味竞赛", "28": "存档查询",
        "29": "戴夫厨房", "30": "聚宝盆",
        "31": "僵局逃脱", "32": "幸运宝藏",
        "33": "全商店购买", "34": "查榜",
        "35": "黄瓜", "36": "金币",
        "37": "二倍速", "38": "全头像",
        "39": "豌豆共生", "40": "世界通关",
        "41": "装扮激活", "42": "植物激活升阶",
        "43": "世界植物+装扮", "44": "清除虚拟存档",
        "45": "神秘宝藏", "46": "21亿钻石",
        "47": "版本更新", "48": "uk",
        "49": "全签", "50": "神秘宝藏",
        "q": "退出程序"
    }
    LEFT_WIDTH = 20  
    def display_width(s):
        width = 0
        for char in s:
            if '\u4e00' <= char <= '\u9fff':  
                width += 2
            else:
                width += 1
        return width
    def ljust_visual(s, width):
        current_width = display_width(s)
        if current_width >= width:
            return s
        padding = ' ' * (width - current_width)
        return s + padding
    item_0_prefix = " 0: "
    item_0 = f"{item_0_prefix}{menu_items['0']}"
    print(item_0)
    other_keys = [k for k in menu_items.keys() if k != "0"]
    other_keys.sort(key=lambda x: int(x) if x.isdigit() else float('inf'))
    for i in range(0, len(other_keys), 2):
        left_key = other_keys[i]
        left_text = menu_items[left_key]
        if len(left_key) == 1:
            left_prefix = f" {left_key}: "
        else:
            left_prefix = f" {left_key}:"
        left_full = f"{left_prefix}{left_text}"
        left_formatted = ljust_visual(left_full, LEFT_WIDTH)
        if i + 1 < len(other_keys):
            right_key = other_keys[i + 1]
            right_text = menu_items[right_key]
            if len(right_key) == 1:
                right_prefix = f" {right_key}: "
            else:
                right_prefix = f" {right_key}:"
            right_full = f"{right_prefix}{right_text}"
            print(f"{left_formatted}{right_full}")
        else:
            print(left_formatted)
    print("=" * 60)
    if latency != 0:
        print(f"当前加解密延迟:{latency:.1f}ms  ㅤ游戏延迟:{latency_拓维:.1f}ms")
    
    print("请选择要执行的任务:")

def call_functions(choices):
    for choice in choices:
        if choice == "1":
            每天日常()
        elif choice == "2":
            make_进入探险()
            make_探险() 
        elif choice == "3":
            双人对决()
        elif choice == "4":
            游园花会()
        elif choice == "5":
            欢乐砸罐()
        elif choice == "6":
            回忆之旅()
        elif choice == "7":
            创意庭院()
        elif choice == "8":
            潘妮追击()
        elif choice == "9":
            时空秘境()
        elif choice == "10":
            秘宝()
        elif choice == "11":
            无尽挑战()
        elif choice == "12":
            make_欢乐植树()
        elif choice == "13":
            make_领取神器()
        elif choice == "14":
            挂件()
        elif choice == "15":
            超Z联赛()
        elif choice == "16":
            make_领取302钻石
        elif choice == "17":
            make_问卷调查()
        elif choice == "18":
            make_兑换码()  
        elif choice == "19":
            make_邮箱()
        elif choice == "20":
            新人()
        elif choice == "21":
            僵博挑战()
        elif choice == "22":
            三月同游()
        elif choice == "23":
            make_原木宝箱()
        elif choice == "24":
            踏青响叮当()
        elif choice == "25":
            make_转基因全()
        elif choice == "26":
            家族()
        elif choice == "27":
            趣味竞赛()
        elif choice == "28":
            查询货币()
        elif choice == "29":
            make_戴夫厨房()
        elif choice == "30":
            聚宝盆()
        elif choice == "31":
            僵局逃脱()
        elif choice == "32":
            make_幸运宝藏()
        elif choice == "33":
            make_购买()
        elif choice == "34":
            make_榜单()
        elif choice == "35":
            make_黄瓜()
        elif choice == "36":
            make_金币()
        elif choice == "37":
            make_2倍速()
        elif choice == "38":
            make_全头像()
        elif choice == "39":
            make_豌豆共生()
        elif choice == "40":
            make_注入世界()
        elif choice == "41":
            make_植物装扮激活()
        elif choice == "42":
            植物激活升阶()
        elif choice == "43":
            世界植物装扮()
        elif choice == "44":
            make_清虚存档()
        elif choice == "45":
            make_神秘宝藏()
        elif choice == "46":
            make_21亿负钻石()
        elif choice == "47":
            make_版本更新()
        elif choice == "48":
            make_ukugd()
        elif choice == "49":
            make_补签()
        elif choice == "50":
            make_神秘宝藏()
        elif choice == "0":
            make_官服改密()
        elif choice == 'q':
            print("退出程序")
            return False
    return True
#===========================每天日常======================
def 每天日常():
    make_碎片挑战()
    make_七天签到()
    make_每周神秘水晶2w()
    make_充值返利()
    make_签到()
    make_每日领钻石装扮券()
    make_踏春之旅任务()
    make_免费箱子()
    make_双人每日每周()
    make_点击庭院()
    make_庭院游玩币()
    make_砸罐任务()
    make_聚宝盆()
    make_每日神秘水晶()
    make_每日联赛钥匙()
    make_戴夫厨房()
    input("日常任务已全部完成，按回车退出")

#===========================潘妮追击======================
def 潘妮追击():
    title = "《潘妮追击》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 每周打14万分领取700钻",
        "2: 追击每日60钻",
        "3: 修改追击分数",
        "4: 刷追击币",
        "5: 刷币买神器材料",
        "6: 买电池和查询电池数量",
        "7: 查看追击排行榜",
        "8: 查看追击每关分数",
        "9: 追击商店购买",
        "10: 追击指南",
        "11: 潘妮追击指南",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_追击14w分_700钻()
    elif sub_choice == '2':
        make_追击每日()
    elif sub_choice == '3':
        make_追击分数主程序()
    elif sub_choice == '4':
        make_追击币()
    elif sub_choice == '5':
        make_全自动买材料()
    elif sub_choice == '6':
        make_买电池()
    elif sub_choice == '7':
        make_追击排行榜()
    elif sub_choice == '8':
        make_查询追击每关分数()
    elif sub_choice == '9':
        make_查询追击分数()
    elif sub_choice == '10':
        make_追击商店购买()
    elif sub_choice == '11':
        make_潘妮追击指南()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================春夏秋冬庆典======================
def 游园花会():
    title = "《踏春之旅》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 任务",
        "2: 令营转盘",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == "q":
        return
    elif sub_choice == '1':
        make_踏春之旅任务()
    elif sub_choice == '2':
        make_令营抽奖()
    else:
        print("无效的选择，请重新选择")
        return

#===========================双人对决======================
def 双人对决():
    title = "《双人对决》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 上宗师段位",
        "2: 双人对决每日每周任务",
        "3: 双人抽奖",
        "4: 双人胜败查询",
        "5: 基因抽奖",
        "6: 基因升级",
        "7: 双人宗师奖励",
        "8: 僵尸升级",
        "9: 双人商店",
        "10: 查询双人僵尸",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_一键宗师()
    elif sub_choice == '2':
        make_双人每日每周()
    elif sub_choice == '3':
        make_双人抽奖()
    elif sub_choice == '4':
        make_双人胜败查询()
    elif sub_choice == '5':
        make_基因抽取()
    elif sub_choice == '6':
        make_基因升级()
    elif sub_choice == '7':
        make_双人段位奖励()
    elif sub_choice == '8':
        make_僵尸升级()
    elif sub_choice == '9':
        make_双人商店()
    elif sub_choice == '10':
        make_查双人僵尸()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================欢乐砸罐======================
def 欢乐砸罐():
    title = "《欢乐砸罐》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 砸罐任务",
        "2: 砸罐子",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_砸罐任务()
    elif sub_choice == '2':
        make_砸罐子()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================回忆之旅======================
def 回忆之旅():
    title = "《回忆之旅》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 普通关",
        "2: 困难关",
        "3: 成就完成",
        "4: 成就奖励",
        "5: 商店购买",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_周回忆普通关()
    elif sub_choice == '2':
        make_回忆困难()
    elif sub_choice == '3':
        make_回忆成就()
    elif sub_choice == '4':
        make_回忆奖励()
    elif sub_choice == '5':
        make_回忆之旅商店()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return



#===========================时空秘境======================
def 时空秘境():
    title = "《童话森林》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 第一章普通",
        "2: 第一章困难",
        "3: 第二章普通",
        "4: 第二章困难",
        "5: 41平行宇宙普通",
        "6: 41平行宇宙困难",
        "7: 41平行宇宙刷币",
        "8: 儿童节普通",
        "9: 儿童节困难",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_童话森林第一章普通()
    elif sub_choice == '2':
        make_童话森林第一章困难()
    elif sub_choice == '3':
        make_童话森林第二章普通()
    elif sub_choice == '4':
        make_童话森林第二章困难()
    elif sub_choice == '5':
        make_平行宇宙普通()
    elif sub_choice == '6':
        make_平行宇宙困难()
    elif sub_choice == '7':
        make_平行宇宙无限刷币()
    elif sub_choice == '8':
        make_儿童节秘境普通()
    elif sub_choice == '9':
        make_儿童节秘境困难()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================秘宝======================
def 秘宝():
    print(f"  1: 潘妮宝箱")
    print(f"  2: 秘宝")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_潘妮宝箱()
    elif sub_choice == "2":
        make_秘宝抽奖()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================创意庭院======================
def 创意庭院():
    title = "《创意庭院》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 点400赞",
        "2: 自创关卡删除点400赞",
        "3: 发布庭院关",
        "4: 查询自己关卡删除",
        "5: 3.6.3版本买名片",
        "6: 庭院商店",
        "7: 创意庭院榜单",
        "8: 查询关卡",
        "9: 关卡删除",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_庭院点赞(id_庭院, skip_line=False, skip_游玩=False)
    elif sub_choice == '2':
        make_自动庭院主程序()
    elif sub_choice == '3':
        make_随机庭院关()
    elif sub_choice == '4':
        make_查询庭院()
    elif sub_choice == '5':
        make_名片()
    elif sub_choice == '6':
        make_庭院商店()
    elif sub_choice == '7':
        make_庭院榜单()
    elif sub_choice == '8':
        make_查询庭院关卡()
    elif sub_choice == '9':
        make_删除关卡()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================无尽挑战======================
def 无尽挑战():
    title = "《无尽挑战》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 无尽通关",
        "2: 买培养液",
        "3: 无尽挑战(新)",
        "4: 无尽任务",
        "5: 无尽榜单查询",
        "6: 无尽商店购买",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        全自动无尽()
    elif sub_choice == '2':
        make_全自动培养液()
    elif sub_choice == '3':
        make_循环无尽另()
    elif sub_choice == '4':
        make_无尽任务()
    elif sub_choice == '5':
        make_无尽榜单()
    elif sub_choice == '6':
        make_无尽商店购买()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return
#===========================超Z联赛======================
def 超Z联赛():
    title = "《超Z联赛》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 每日联赛钥匙",
        "2: 联赛必赢(1钥匙=5奖杯)",
        "3: 购买1联赛钥匙(30钻)",
        "4: 超Z榜单",
        "5: 超Z商店",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_每日联赛钥匙()
    elif sub_choice == '2':
        make_自动联赛主程序()
    elif sub_choice == '3':
        make_超z买钥匙()
    elif sub_choice == '4':
        make_超Z榜单()
    elif sub_choice == '5':
        make_超Z商店()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================追击指南======================
def 聚宝盆():
    print(f"  1: 聚宝盆任务") 
    print(f"  2: 聚宝盆抽奖")
    print(f"  3: 聚宝盆商店")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_聚宝盆()
    elif sub_choice == '2':
        make_聚宝盆抽奖()
    elif sub_choice == '3':
        make_聚宝盆商店()
    elif sub_choice == "q":
        return 



#===========================七日指南======================
def 七日指南():
    print(f"  1: 七天任务")
    print(f"  2: 进度条奖励")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_七日指南()
    elif sub_choice == '2':
        make_七日指南奖励()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        七日指南()

#===========================潘妮课堂======================
def 潘妮课堂():
    print(f"  1: 答题和关卡通关")
    print(f"  2: 课堂币买植物")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_潘妮课堂()
    elif sub_choice == '2':
        make_潘妮课堂买植物()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        潘妮课堂()

#===========================三月同游======================
def 三月同游():
    title = "《三月同游》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 个人任务",
        "2: 日常任务",
        "3: 每月任务",
        "4: 收取同游币",
        "5: 同游商店",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_十月同游个人()
    elif sub_choice == '2':
        make_十月同游日常()
    elif sub_choice == '3':
        make_十月同游每月()
    elif sub_choice == '4':
        make_收取同游币()
    elif sub_choice == '5':
        make_同游商店()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return
#===========================踏春响叮当======================
def 踏青响叮当():
    title = "《六一响叮当》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 火焰训练",
        "2: 电击训练",
        "3: 物理训练",
        "4: 奖励领取",
        "5: 踏青响叮当榜单",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_火焰训练()
    elif sub_choice == '2':
        make_电击训练()
    elif sub_choice == '3':
        make_物理训练()
    elif sub_choice == '4':
        make_响叮当奖励()
    elif sub_choice == '5':
        make_响叮当榜单()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================趣味竞赛======================
def 趣味竞赛():
    title = "《植树节趣味竞赛》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 空中战争",
        "2: 记忆骆驼牌",
        "3: 坚果保龄球",
        "4: 猜猜我是谁",
        "5: 汽车华容道",
        "6: 无限刷能量",
        "7: 奖励领取",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_趣味竞赛空中战争()
    elif sub_choice == '2':
        make_趣味竞赛记忆骆驼牌()
    elif sub_choice == '3':
        make_趣味竞赛坚果保龄球()
    elif sub_choice == '4':
        make_趣味竞赛猜猜我是谁()
    elif sub_choice == '5':
        make_趣味竞赛汽车华容道()
    elif sub_choice == '6':
        make_植树节趣味竞赛无限刷币()
    elif sub_choice == '7':
        make_趣味竞赛奖励()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================查询======================
def 查询货币():
    title = "《查询》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 查询部分货币",
        "2: 查询植物碎片",
        "3: 查询植物",
        "4: 查询神器",
        "5: 查询僵尸",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_查询货币()
    elif sub_choice == '2':
        make_查询碎片()
    elif sub_choice == '3':
        make_查询植物()
    elif sub_choice == '4':
        make_查询神器()
    elif sub_choice == '5':
        make_查双人僵尸()
    elif sub_choice == 'q':
        return
    else:
        print("无效的选择，请重新选择")
        return

#===========================家族======================
def 家族():
    print(f"  1: 手动刷新")
    print(f"  2: 全自动(1个词条)")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_家族()
    elif sub_choice == "2":
        make_全自动刷新家族()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return
#===========================僵博挑战======================
def 僵博挑战():
    print(f"  1: 刷蓝水晶24个")
    print(f"  2: 蓝水晶抽奖24次")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_蓝宝石()
    elif sub_choice == '2':
        make_蓝宝石抽奖()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return
#===========================僵局逃脱======================
def 僵局逃脱():
    print(f"  1: 通关")
    print(f"  2: 领奖励")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_僵局逃脱()
    elif sub_choice == '2':
        make_僵局逃脱奖励()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

def make_榜单():
    title = "《榜单》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 超Z榜单",
        "2: 庭院榜单",
        "3: 响叮当榜",
        "4: 追击榜",
        "5: 无尽榜",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_超Z榜单()
    elif sub_choice == '2':
        make_庭院榜单()
    elif sub_choice == '3':
        make_响叮当榜单()
    elif sub_choice == '4':
        make_追击排行榜()
    elif sub_choice == '5':
        make_无尽榜单()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

def make_购买():
    title = "《购买》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 水晶商店",
        "2: 潘妮商店",
        "3: 超Z商店",
        "4: 庭院商店",
        "5: 聚宝盆商店",
        "6: 同游商店",
        "7: 双人对决商店",
        "8: 无尽商店",
        "9: 追击商店",
        "10: 回忆之旅商店",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_水晶商店()
    elif sub_choice == '2':
        make_潘妮商店()
    elif sub_choice == '3':
        make_超Z商店()
    elif sub_choice == '4':
        make_庭院商店()
    elif sub_choice == '5':
        make_聚宝盆商店()
    elif sub_choice == '6':
        make_同游商店()
    elif sub_choice == '7':
        make_双人商店()
    elif sub_choice == '8':
        make_无尽商店购买()
    elif sub_choice == '9':
        make_追击商店购买()
    elif sub_choice == '10':
        make_回忆之旅商店()
    elif sub_choice == 'q':
        return
    else:
        print("无效的选择，请重新选择")
        return
def make_转基因全():
    print(f"  1: 单独转基因")
    print(f"  2: 自动转基因")
    print(f"  3: 装扮转基因")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_转基因()
    elif sub_choice == '2': 
        make_自动转基因()
    elif sub_choice == '3':
        make_植物装扮转基因()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

def 新人():
    title = "《新人》"
    print(title.center(60))
    print("=" * 60)
    menu_items = [
        "1: 7天签到",
        "2: 7天任务",
        "3: 潘妮课堂",
        "4: 新手商店",
        "5: 激活新人活动",
        "6: 七天任务详情",
        "q: 返回主菜单"
    ]
    print_grouped(menu_items, 2, col_width=25)
    print("=" * 60)
    sub_choice = input("请选择功能: ").strip()
    if sub_choice == '1':
        make_新人七天签到()
    elif sub_choice == '2':
        七日指南()
    elif sub_choice == '3':
        make_潘妮课堂()
    elif sub_choice == '4':
        make_新人商店()
    elif sub_choice == '5':
        make_激活新人活动()
    elif sub_choice == '6':
        make_七天指南详情()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

def 植物激活升阶():
    print(f"  1: 植物激活")
    print(f"  2: 植物升阶")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_植物激活()
    elif sub_choice == '2':
        make_植物升阶()
    elif sub_choice == "q": 
        return
    else:
        print("无效的选择，请重新选择")
        return

def 世界植物装扮():
    print(f"  1: 世界植物激活")
    print(f"  2: 世界装扮激活")
    print(f"  q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_世界植物()
    elif sub_choice == '2':
        make_世界关卡装扮()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return

def 挂件():
    print(f" 1: 普通挂件")
    print(f" 2: 红色挂件")
    print(f" q: 返回主菜单")
    sub_choice = input("请选择功能: ")
    if sub_choice == '1':
        make_普通挂件()
    elif sub_choice == '2':
        make_红色挂件()
    elif sub_choice == "q":
        return
    else:
        print("无效的选择，请重新选择")
        return









def main():
    while True:
        display_menu()
        choices = input("请输入选项编号:").split()
        if 'q' in choices:
            break
        filtered_choices = [c for c in choices if c != 'q']
        if call_functions(filtered_choices):
            print("请再次选择。")


if __name__ == "__main__":
    main()