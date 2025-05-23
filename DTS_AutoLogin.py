# Campus Network Auto Login Script
import requests
import urllib.parse
from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_v1_5 # Not used for raw RSA pow(m,e,n)
import binascii
import math
import configparser
import os
import re

# --- Global Configuration (Defaults, can be overridden by config.ini for some) ---
BASE_URL_DEFAULT = "http://172.16.200.101/eportal/"
MAC_ADDRESS_DEFAULT = "111111111"
SERVICE_NAME_DEFAULT = ""
OPERATOR_ID_DEFAULT = ""
OPERATOR_PASSWORD_DEFAULT = ""
CAPTIVE_PORTAL_DETECTION_URL = "http://www.msftconnecttest.com/redirect"
CONFIG_FILE_NAME = "config.ini"


# --- End Global Configuration ---

def load_or_create_config():
    """Loads credentials and settings from config.ini or creates it with default values."""
    config = configparser.ConfigParser()

    # Default values
    defaults = {
        'username': '1',
        'password': '1',
        'base_url': BASE_URL_DEFAULT,
        'mac_address': MAC_ADDRESS_DEFAULT,
        'service_name': SERVICE_NAME_DEFAULT,
        'operator_id': OPERATOR_ID_DEFAULT,
        'operator_password': OPERATOR_PASSWORD_DEFAULT,
        'query_string_manual': ''  # Ensure this is part of defaults if used
    }

    loaded_settings = defaults.copy()

    if os.path.exists(CONFIG_FILE_NAME):
        try:
            config.read(CONFIG_FILE_NAME)
            if 'Settings' in config:
                for key in defaults:  # Use defaults.keys() to ensure all expected keys are checked
                    loaded_settings[key] = config['Settings'].get(key, defaults[key])
            else:
                print(f"Section [Settings] not found in {CONFIG_FILE_NAME}. Using defaults and creating section.")
                config['Settings'] = defaults  # Assign all defaults to the new section
                with open(CONFIG_FILE_NAME, 'w') as configfile:
                    config.write(configfile)
                print(f"Please update {CONFIG_FILE_NAME} with your actual settings.")
        except configparser.Error as e:
            print(f"Error reading {CONFIG_FILE_NAME}: {e}. Using default settings.")
            # In case of read error, try to re-create with defaults if section is missing or file is corrupt
            if 'Settings' not in config:  # Check if section exists before trying to assign
                config['Settings'] = {}  # Create section if it doesn't exist
            for key, value in defaults.items():  # Ensure all default keys are present in the config object
                config['Settings'][key] = config['Settings'].get(key, value)  # Get existing or set default
            try:
                with open(CONFIG_FILE_NAME, 'w') as configfile:  # Write out the potentially repaired config
                    config.write(configfile)
                print(
                    f"Re-created/Repaired {CONFIG_FILE_NAME} with default/merged settings. Please update it if necessary.")
            except IOError:
                print(f"Could not write {CONFIG_FILE_NAME}. Please check permissions.")
    else:
        print(f"{CONFIG_FILE_NAME} not found. Creating it with default settings.")
        config['Settings'] = defaults
        try:
            with open(CONFIG_FILE_NAME, 'w') as configfile:
                config.write(configfile)
            print(f"Please update {CONFIG_FILE_NAME} with your actual settings.")
        except IOError:
            print(f"Could not write {CONFIG_FILE_NAME}. Please check permissions.")
            print("Using default settings for this session.")

    return loaded_settings


def get_query_string_from_captive_portal(detection_url):
    """
    Attempts to get the redirect URL's query string from a captive portal
    by parsing JavaScript within an HTTP 200 OK HTML response.
    """
    print(f"\nAttempting to detect captive portal and get QUERY_STRING via: {detection_url}")
    try:
        response = requests.get(detection_url, timeout=10, allow_redirects=True)

        if response.status_code == 200:
            # Try to find the redirect URL in JavaScript
            # Example: <script>top.self.location.href='http://...'</script>
            match = re.search(r"top\.self\.location\.href=['\"]([^'\"]+)['\"]", response.text)
            if match:
                redirect_url = match.group(1)
                print(f"Detected redirect URL in JS: {redirect_url}")
                parsed_url = urllib.parse.urlparse(redirect_url)
                if parsed_url.query:
                    print(f"Successfully extracted QUERY_STRING: {parsed_url.query}")
                    return parsed_url.query
                else:
                    print("Could not extract query string from the JS redirect URL.")
                    return None
            else:
                print("No JavaScript redirect found in the response from detection URL.")
                print("This might mean you are already connected, or the portal detection failed.")
                # Check if the response URL itself is the login page (after some non-JS redirects)
                final_url_parsed = urllib.parse.urlparse(response.url)
                if "eportal/index.jsp" in response.url and final_url_parsed.query:  # Common portal path
                    print(f"Using query string from final response URL: {final_url_parsed.query}")
                    return final_url_parsed.query
                return None
        else:
            print(f"Unexpected status code {response.status_code} from detection URL.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error during captive portal detection: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during captive portal detection: {e}")
        return None


def get_page_info(session, base_url, query_string):  # Added session parameter
    """Fetches page information (like RSA keys and encryption status)."""
    page_info_url = urllib.parse.urljoin(base_url, "InterFace.do?method=pageInfo")

    # queryString for pageInfo should be single encoded
    payload_str = f"queryString={urllib.parse.quote_plus(query_string)}"

    parsed_base_url = urllib.parse.urlparse(base_url)
    origin_host = parsed_base_url.hostname

    # Construct Origin to match captured request (scheme://hostname without non-standard port)
    dynamic_origin = f"{parsed_base_url.scheme}://{origin_host}"

    # Construct Referer to match captured request
    # (scheme://hostname/eportal/index.jsp?original_query_string)
    referer_path = "/eportal/index.jsp"
    dynamic_referer = f"{parsed_base_url.scheme}://{origin_host}{referer_path}?{query_string}"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        # Updated UA
        "Referer": dynamic_referer,
        "Origin": dynamic_origin,
        "Accept": "*/*"  # Added Accept
    }

    print(f"\nFetching page info from: {page_info_url}")
    # print(f"With Headers: {headers}") # For debugging, can be noisy
    # print(f"With Payload: {payload_str}") # For debugging
    try:
        response = session.post(page_info_url, data=payload_str, headers=headers, timeout=10)  # Use session.post
        response.raise_for_status()  # Will raise an HTTPError for bad responses (4xx or 5xx)
        page_info = response.json()
        print("Page info received successfully.")
        return page_info
    except requests.exceptions.HTTPError as e:  # More specific exception for HTTP errors
        print(f"HTTP error fetching page info: {e}")
        if e.response is not None:
            print(f"Response Status Code (HTTPError): {e.response.status_code}")
            print(f"Response Text (HTTPError): {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:  # Catch other request exceptions (timeout, connection error, etc.)
        print(f"Error fetching page info: {e}")
        # For RequestException, response might not be available or fully formed.
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response Status Code (RequestException): {e.response.status_code}")
            print(f"Response Text (RequestException): {e.response.text}")
        return None
    except ValueError as e:  # For JSON decoding errors
        print(f"Error decoding page info JSON: {e}")
        # response variable should be available here if post was successful but content wasn't JSON
        if 'response' in locals() and response is not None:
            print(f"Response Status Code (ValueError): {response.status_code}")
            print(f"Response Text (ValueError): {response.text}")
        return None


def attempt_DTS_AutoLogin(settings, session):
    """
    Attempts to perform the campus network login.
    Args:
        settings (dict): A dictionary containing configuration like username, password, etc.
        session (requests.Session): An active requests session object.
    Returns:
        dict: A dictionary with keys 'success' (bool) and 'message' (str),
              and optionally 'details' (dict) from login_result.
    """
    username = settings['username']
    password = settings['password']
    base_url = settings['base_url']
    # mac_address is determined later based on query_string or config
    service_name = settings['service_name']
    operator_id = settings['operator_id']
    operator_password = settings['operator_password']

    # For GUI logging, we might want to collect messages instead of just printing.
    # For now, existing prints will serve for CLI, GUI can capture stdout if needed or we can add explicit logging.
    # log_messages = [] # Example for collecting logs

    if username == "1" or password == "1":
        # msg = f"警告: 使用默认用户名/密码 ('1')。请确保 {CONFIG_FILE_NAME} 已更新为您的实际凭据。"
        print(f"\n警告: 使用默认用户名/密码 ('1')。请确保 {CONFIG_FILE_NAME} 已更新为您的实际凭据。")
        # log_messages.append(msg)

    print(f"\n使用用户名: {username}")
    print(f"使用 Base URL: {base_url}")
    # log_messages.append(f"使用用户名: {username}, Base URL: {base_url}")

    current_query_string = get_query_string_from_captive_portal_with_session(session, CAPTIVE_PORTAL_DETECTION_URL)

    if not current_query_string:
        # msg = "警告: 未能从强制门户自动检测到 QUERY_STRING。"
        print("\n警告: 未能从强制门户自动检测到 QUERY_STRING。")
        # log_messages.append(msg)

        manual_qs = settings.get('query_string_manual', '')
        if manual_qs:
            current_query_string = manual_qs
            # msg = f"尝试使用 {CONFIG_FILE_NAME} 中手动配置的 'query_string_manual': {current_query_string}"
            print(f"尝试使用 {CONFIG_FILE_NAME} 中手动配置的 'query_string_manual': {current_query_string}")
            # log_messages.append(msg)
        else:
            # msg = f"错误: 没有可用的 QUERY_STRING (既未自动检测到，也未在 {CONFIG_FILE_NAME} 中手动配置)。正在中止。"
            print(f"错误: 没有可用的 QUERY_STRING (既未自动检测到，也未在 {CONFIG_FILE_NAME} 中手动配置)。正在中止。")
            # log_messages.append(msg)
            return {"success": False, "message": "没有可用的 QUERY_STRING"}  # Simplified message for return
    else:
        # msg = f"使用自动检测到的 query_string: {current_query_string}"
        print(f"使用自动检测到的 query_string: {current_query_string}")
        # log_messages.append(msg)

    mac_address_from_config = settings.get('mac_address', MAC_ADDRESS_DEFAULT)
    mac_address_for_encryption = mac_address_from_config
    mac_param_name_in_qs = 'mac'

    if current_query_string:
        try:
            parsed_qs = urllib.parse.parse_qs(current_query_string)
            if mac_param_name_in_qs in parsed_qs and parsed_qs[mac_param_name_in_qs]:
                mac_from_qs = parsed_qs[mac_param_name_in_qs][0]
                # msg = f"在 query_string 中找到 '{mac_param_name_in_qs}': '{mac_from_qs}'。将此用于加密。"
                print(f"在 query_string 中找到 '{mac_param_name_in_qs}': '{mac_from_qs}'。将此用于加密。")
                # log_messages.append(msg)
                mac_address_for_encryption = mac_from_qs
            else:
                # msg = f"在 query_string 中未找到 '{mac_param_name_in_qs}'。使用配置中的 MAC: '{mac_address_from_config}'"
                print(
                    f"在 query_string 中未找到 '{mac_param_name_in_qs}'。使用配置中的 MAC: '{mac_address_from_config}'")
                # log_messages.append(msg)
        except Exception as e:
            # msg = f"从 query_string 解析 MAC 时出错: {e}。使用配置中的 MAC: '{mac_address_from_config}'"
            print(f"从 query_string 解析 MAC 时出错: {e}。使用配置中的 MAC: '{mac_address_from_config}'")
            # log_messages.append(msg)
    else:  # Should not happen if previous checks are correct, but defensive.
        # msg = f"没有可用于解析 '{mac_param_name_in_qs}' 的 query_string。使用配置中的 MAC: '{mac_address_from_config}'"
        print(f"没有可用于解析 '{mac_param_name_in_qs}' 的 query_string。使用配置中的 MAC: '{mac_address_from_config}'")
        # log_messages.append(msg)

    # msg = f"最终用于加密的 MAC/ID: '{mac_address_for_encryption}'"
    print(f"最终用于加密的 MAC/ID: '{mac_address_for_encryption}'")
    # log_messages.append(msg)

    parsed_base_url_for_cookie = urllib.parse.urlparse(base_url)
    cookie_fetch_host_part = f"{parsed_base_url_for_cookie.scheme}://{parsed_base_url_for_cookie.hostname}"
    cookie_fetch_url = f"{cookie_fetch_host_part}/eportal/index.jsp?{current_query_string}"

    # msg = f"\n尝试通过访问以下网址预取 Cookie: {cookie_fetch_url}"
    print(f"\n尝试通过访问以下网址预取 Cookie: {cookie_fetch_url}")
    # log_messages.append(msg.strip())

    headers_for_cookie_fetch = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    }
    try:
        cookie_response = session.get(cookie_fetch_url, headers=headers_for_cookie_fetch, timeout=10,
                                      allow_redirects=True)
        # msg = f"对 {cookie_fetch_url} 的 Cookie 预取请求已完成，状态: {cookie_response.status_code}"
        print(f"对 {cookie_fetch_url} 的 Cookie 预取请求已完成，状态: {cookie_response.status_code}")
        # log_messages.append(msg)
        # msg = f"预取后的会话 Cookie: {session.cookies.get_dict()}"
        print(f"预取后的会话 Cookie: {session.cookies.get_dict()}")  # Keep for CLI debugging
        # log_messages.append(msg) # Cookie details might be too verbose for GUI log

        cookie_domain_to_set = parsed_base_url_for_cookie.hostname
        app_path = parsed_base_url_for_cookie.path
        if not app_path or not app_path.startswith('/'):
            app_path = "/"
        if not app_path.endswith('/') and app_path != "/":
            app_path += '/'

        cookies_to_set_manually = {
            "EPORTAL_COOKIE_SAVEPASSWORD": "false", "EPORTAL_COOKIE_SERVER": "", "EPORTAL_COOKIE_DOMAIN": "",
            "EPORTAL_COOKIE_OPERATORPWD": "", "EPORTAL_AUTO_LAND": "", "EPORTAL_COOKIE_USERNAME": "",
            "EPORTAL_COOKIE_PASSWORD": "", "EPORTAL_COOKIE_NEWV": "", "EPORTAL_USER_GROUP": "",
            "EPORTAL_COOKIE_SERVER_NAME": ""
        }
        # msg = f"\n为域手动设置其他 Cookie: {cookie_domain_to_set}, 路径: {app_path}"
        print(f"\n为域手动设置其他 Cookie: {cookie_domain_to_set}, 路径: {app_path}")
        # log_messages.append(msg.strip())
        for name, value in cookies_to_set_manually.items():
            session.cookies.set(name, value, domain=cookie_domain_to_set, path=app_path)
        # msg = f"手动添加后的会话 Cookie: {session.cookies.get_dict()}"
        print(f"手动添加后的会话 Cookie: {session.cookies.get_dict()}")  # Keep for CLI debugging
        # log_messages.append(msg)

    except requests.exceptions.RequestException as e_cookie:
        # msg = f"警告: 从 {cookie_fetch_url} 预取 Cookie 时出错: {e_cookie}"
        print(f"警告: 从 {cookie_fetch_url} 预取 Cookie 时出错: {e_cookie}")
        # log_messages.append(msg)
        # Continue, as login might still work or fail gracefully later

    page_info = get_page_info(session, base_url, current_query_string)

    if not page_info:
        # msg = "未能获取页面信息。正在中止。"
        print("未能获取页面信息。正在中止。")
        # log_messages.append(msg)
        return {"success": False, "message": "未能获取页面信息"}

    password_encrypt_enabled = page_info.get("passwordEncrypt") == "true"
    public_key_exponent = page_info.get("publicKeyExponent")
    public_key_modulus = page_info.get("publicKeyModulus")

    # msg = f"\n密码加密已启用: {password_encrypt_enabled}"
    print(f"\n密码加密已启用: {password_encrypt_enabled}")
    # log_messages.append(msg.strip())

    password_for_request = password

    if password_encrypt_enabled:
        if not public_key_exponent or not public_key_modulus:
            # msg = "错误: 在 page_info 中未找到 RSA 公钥组件 (exponent/modulus)，但加密已启用。"
            print("错误: 在 page_info 中未找到 RSA 公钥组件 (exponent/modulus)，但加密已启用。")
            # log_messages.append(msg)
            return {"success": False, "message": "RSA 公钥组件缺失"}

        # msg = f"RSA Exponent: {public_key_exponent}"
        print(f"RSA Exponent: {public_key_exponent}")
        # log_messages.append(msg) # Exponent/Modulus might be too verbose
        # msg = f"RSA Modulus: {public_key_modulus[:30]}..."
        print(f"RSA Modulus: {public_key_modulus[:30]}...")
        # log_messages.append(msg)

        password_to_encrypt_js_style = password + ">" + mac_address_for_encryption  # Use the determined mac_address_for_encryption
        reversed_password_to_encrypt = password_to_encrypt_js_style[::-1]

        encrypted_pass = encrypt_password(
            reversed_password_to_encrypt,
            public_key_exponent,
            public_key_modulus
        )
        if not encrypted_pass:
            # msg = "密码加密失败。正在中止。"
            print("密码加密失败。正在中止。")
            # log_messages.append(msg)
            return {"success": False, "message": "密码加密失败"}

        # msg = f"加密后的密码 (前30个字符): {encrypted_pass[:30]}..."
        print(f"加密后的密码 (前30个字符): {encrypted_pass[:30]}...")
        # log_messages.append(msg)
        password_for_request = encrypted_pass

    login_result_data = perform_login(  # This function now returns the result
        session,
        base_url,
        username,
        password_for_request,
        service_name,
        current_query_string,
        operator_id,
        operator_password,
        password_encrypt_enabled
    )

    if not login_result_data:
        # msg = "登录请求失败或解码响应时出错。"
        print("登录请求失败或解码响应时出错。")
        # log_messages.append(msg)
        return {"success": False, "message": "登录请求失败或响应无效"}

    # CLI print for login_result_data is inside perform_login,
    # but we need to construct a summary for the return value.
    if login_result_data.get("result") == "success":
        # msg = "登录成功!"
        # print(msg) # Already printed in perform_login
        # log_messages.append(msg)
        # ... other detail prints ...
        return {"success": True, "message": login_result_data.get('message', "登录成功!"), "details": login_result_data}
    else:
        # msg = "登录失败。"
        # print(msg) # Already printed in perform_login
        # log_messages.append(msg)
        # ... other detail prints ...
        return {"success": False, "message": login_result_data.get('message', "登录失败。"),
                "details": login_result_data}


def main():
    """Main function to perform login, for standalone script execution."""
    print("校园网自动登录脚本")
    print("=" * 30)

    settings = load_or_create_config()

    # Create a new session for each standalone run
    # Using 'with' ensures the session is closed if it were to implement __exit__
    # requests.Session() itself doesn't need to be closed via 'with' but it's good practice if it did.
    session = requests.Session()
    try:
        login_status = attempt_DTS_AutoLogin(settings, session)
    finally:
        session.close()  # Explicitly close the session

    print("\n最终登录尝试状态:")
    if login_status.get("success"):  # Check .get("success") as key might be missing if error before return
        print("成功!")
    else:
        print("失败.")

    print("消息:", login_status.get("message", "无消息。"))

    if "details" in login_status and login_status["details"]:
        print("服务器响应详情:", login_status["details"])


# Modify get_query_string_from_captive_portal to accept and use session
def get_query_string_from_captive_portal_with_session(session, detection_url):
    """
    Attempts to get the redirect URL's query string from a captive portal
    by parsing JavaScript within an HTTP 200 OK HTML response, using a session.
    """
    print(f"\nAttempting to detect captive portal and get QUERY_STRING via: {detection_url}")
    try:
        response = session.get(detection_url, timeout=10, allow_redirects=True)  # Use session.get

        if response.status_code == 200:
            match = re.search(r"top\.self\.location\.href=['\"]([^'\"]+)['\"]", response.text)
            if match:
                redirect_url = match.group(1)
                print(f"Detected redirect URL in JS: {redirect_url}")
                parsed_url = urllib.parse.urlparse(redirect_url)
                if parsed_url.query:
                    print(f"Successfully extracted QUERY_STRING: {parsed_url.query}")
                    return parsed_url.query
                else:
                    print("Could not extract query string from the JS redirect URL.")
                    return None
            else:
                print("No JavaScript redirect found in the response from detection URL.")
                print("This might mean you are already connected, or the portal detection failed.")
                final_url_parsed = urllib.parse.urlparse(response.url)
                if "eportal/index.jsp" in response.url and final_url_parsed.query:
                    print(f"Using query string from final response URL: {final_url_parsed.query}")
                    return final_url_parsed.query
                return None
        else:
            print(f"Unexpected status code {response.status_code} from detection URL.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error during captive portal detection: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during captive portal detection: {e}")
        return None


def double_url_encode(s):
    """Encodes a string twice using urllib.parse.quote_plus."""
    if s is None:
        s = ""
    return urllib.parse.quote_plus(urllib.parse.quote_plus(str(s)))


def perform_login(session, base_url, username, password, service_name, query_string,  # Added session parameter
                  operator_id, operator_password, is_password_encrypted_flag):
    """Performs the login request."""
    login_url = urllib.parse.urljoin(base_url, "InterFace.do?method=login")

    user_id_encoded = double_url_encode(username)
    password_encoded = double_url_encode(password)
    service_encoded = double_url_encode(service_name)
    query_string_encoded = double_url_encode(query_string)
    operator_pwd_encoded = double_url_encode(operator_password)
    operator_user_id_encoded = double_url_encode(operator_id)
    valid_code_encoded = double_url_encode("")
    password_encrypt_str_encoded = double_url_encode(str(is_password_encrypted_flag).lower())

    payload_parts = [
        f"userId={user_id_encoded}",
        f"password={password_encoded}",
        f"service={service_encoded}",
        f"queryString={query_string_encoded}",
        f"operatorPwd={operator_pwd_encoded}",
        f"operatorUserId={operator_user_id_encoded}",
        f"validcode={valid_code_encoded}",
        f"passwordEncrypt={password_encrypt_str_encoded}"
    ]
    payload_str = "&".join(payload_parts)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Referer": base_url
    }

    print(f"\nPerforming login to: {login_url}")
    try:
        response = session.post(login_url, data=payload_str, headers=headers, timeout=15)  # Use session.post
        response.raise_for_status()
        login_result = response.json()  # This is the dict to be returned

        # Print statements for CLI remain, but the function now returns the dict
        print("\n--- 登录结果 ---")
        if login_result.get("result") == "success":
            print("登录成功!")
            print(f"用户索引: {login_result.get('userIndex')}")
            print(f"消息: {login_result.get('message', 'N/A')}")
            if login_result.get("userUrl"):
                print(f"重定向 URL: {login_result.get('userUrl')}")
        else:
            print("登录失败。")
            print(f"结果代码: {login_result.get('result')}")
            print(f"消息: {login_result.get('message', 'N/A')}")
            if login_result.get("validCodeUrl"):
                print("可能需要验证码。新的验证码 URL:", login_result.get("validCodeUrl"))

        return login_result  # Return the JSON response as a dictionary

    except requests.exceptions.RequestException as e:
        print(f"登录请求期间出错: {e}")
        return None
    except ValueError as e:
        print(f"Error decoding login response JSON: {e}")
        if response:
            print(f"Response text: {response.text}")
        return None


def encrypt_password_old_attempt(text_to_encrypt, exponent_hex, modulus_hex):
    # This is the previous attempt, kept for reference if needed.
    try:
        e = int(exponent_hex, 16)
        n = int(modulus_hex, 16)
        key_size_bytes = (n.bit_length() + 7) // 8
        s_bytes = text_to_encrypt.encode('utf-8')
        encrypted_parts = []
        for i in range(0, len(s_bytes), key_size_bytes):
            block_bytes = s_bytes[i: i + key_size_bytes]
            if not block_bytes: continue
            block_int_val = int.from_bytes(block_bytes, byteorder='big')
            if block_int_val >= n:
                print(f"Warning (old_attempt): RSA m ({block_int_val}) >= n ({n}).")
            encrypted_block_int = pow(block_int_val, e, n)
            hex_encrypted_block = format(encrypted_block_int, 'x')
            if len(hex_encrypted_block) % 2 != 0:
                hex_encrypted_block = "0" + hex_encrypted_block
            encrypted_parts.append(hex_encrypted_block)
        return " ".join(encrypted_parts)
    except Exception as ex:
        print(f"Error during (old_attempt) password encryption: {ex}")
        import traceback
        traceback.print_exc()
        return None


def encrypt_password(text_to_encrypt, exponent_hex, modulus_hex):
    """
    Encrypts the password using RSA, attempting to precisely mimic the security.js implementation.
    """
    try:
        e_int = int(exponent_hex, 16)
        n_int = int(modulus_hex, 16)

        # Calculate biHighIndex(m) for n_int to determine js_chunk_size
        # biRadixBits is 16 (bitsPerDigit in JS)
        # biHighIndex(x) is effectively (x.bit_length() - 1) // 16 for a positive integer x
        if n_int == 0:
            # This case should not happen for a valid RSA modulus
            bi_high_idx_m_for_n = 0
        else:
            # (bit_length - 1) gives the position of the MSB (0-indexed).
            # Dividing by 16 gives the index of the 16-bit word containing the MSB.
            bi_high_idx_m_for_n = (n_int.bit_length() - 1) // 16

        # js_chunk_size = 2 * biHighIndex(this.m) in bytes
        js_chunk_size = 2 * bi_high_idx_m_for_n

        if js_chunk_size <= 0:
            print(
                f"Error: Calculated js_chunk_size ({js_chunk_size}) is invalid. Modulus bit length: {n_int.bit_length()}")
            # Fallback or error handling for js_chunk_size.
            # A common RSA key (e.g., 1024-bit) would have n_int.bit_length() approx 1024.
            # (1023 // 16) = 63. js_chunk_size = 2 * 63 = 126.
            # If modulus is too small (e.g. < 16 bits), bi_high_idx_m_for_n could be 0, making js_chunk_size 0.
            # For robustness, if js_chunk_size is problematic, one might default to a conventional size or raise error.
            # Let's use a slightly more robust calculation for chunk size if the above is zero,
            # ensuring it's at least 2, or related to modulus byte length minus some padding.
            # However, strict mimicry requires using the JS logic. If it results in 0, that's a problem.
            # For now, let's assume n_int is large enough.
            # If n_int.bit_length() is 1 to 16, (n_int.bit_length() - 1) // 16 is 0. js_chunk_size = 0.
            # This implies the JS RSA library expects modulus to be > 16 bits.
            if n_int.bit_length() <= 16 and js_chunk_size == 0:  # Modulus too small for this chunking logic
                print(
                    "Warning: Modulus is very small, js_chunk_size calculation resulted in 0. This is likely an issue.")
                print("         The JS library's RSAKeyPair might not support moduli <= 16 bits with its chunking.")
                # We must have a positive chunk size. What would JS do?
                # RSAUtils.setMaxDigits(130) implies it handles large numbers.
                # The issue is if biHighIndex(this.m) is 0.
                # If n_int is 0xFFFF (16 bits), bi_high_idx_m_for_n = (16-1)//16 = 0. chunkSize = 0.
                # This is a flaw in the direct translation if not handled.
                # The JS `encryptedString` would loop `i < al; i += 0`, an infinite loop.
                # Let's assume valid RSA keys where n_int.bit_length() > 16.
                # If js_chunk_size is still 0 for a >16-bit key, something is wrong in bi_high_idx_m_for_n logic.
                # (17-1)//16 = 1. chunkSize = 2. This seems okay.
                # The problem is only for n.bit_length() <= 16.
                # For such small n, RSA is not secure anyway.
                # We will proceed, but if an error occurs due to js_chunk_size being 0, this is the spot.
                if js_chunk_size == 0 and n_int.bit_length() > 0:  # if n_int is not 0 itself
                    print("Error: js_chunk_size is 0, which will cause issues. Aborting encryption.")
                    return None

        # 2. String to character code array
        s_char_codes = [ord(c) for c in text_to_encrypt]

        # 3. Tail padding with 0s
        while len(s_char_codes) % js_chunk_size != 0:
            s_char_codes.append(0)

        al = len(s_char_codes)
        encrypted_hex_parts = []

        # 4. Process in chunks
        for i in range(0, al, js_chunk_size):
            current_chunk_char_codes = s_char_codes[i: i + js_chunk_size]

            # 5. Construct BigInt 'block' from the character code chunk
            # JS: block.digits[j] = a[k++]; block.digits[j] += a[k++] << 8;
            # This means each 'digit' in JS BigInt is 16-bit, formed by two 8-bit chars (low_byte + high_byte << 8)
            block_int_val = 0
            bi_radix = 1 << 16  # 65536

            # Iterate over the chunk of char codes, taking two at a time to form 16-bit digits
            # These digits are then assembled into block_int_val in a little-endian manner
            # (digits[0] is LSW of the BigInt)
            num_digits_in_block = len(current_chunk_char_codes) // 2

            for j_idx in range(num_digits_in_block):
                low_byte = current_chunk_char_codes[2 * j_idx]
                high_byte = current_chunk_char_codes[2 * j_idx + 1]

                digit_val = low_byte + (high_byte << 8)
                block_int_val += digit_val * (bi_radix ** j_idx)

            # 6. RSA operation
            encrypted_block_int = pow(block_int_val, e_int, n_int)

            # 7. Convert encrypted BigInt to hex string
            # Mimicking: text = key.radix == 16 ? RSAUtils.biToHex(crypt) : ...
            # For now, using direct Python hex conversion and padding.
            hex_text = format(encrypted_block_int, 'x')
            if len(hex_text) % 2 != 0:
                hex_text = "0" + hex_text

            encrypted_hex_parts.append(hex_text)

        return " ".join(encrypted_hex_parts)

    except Exception as ex:
        print(f"Error during password encryption: {ex}")
        import traceback
        traceback.print_exc()
        return None


# Helper function to mimic RSAUtils.digitToHex from security.js
def _python_digit_to_hex(n_16bit_digit):
    hex_chars = "0123456789abcdef"  # JS hexToChar is lowercase
    result_chars = []
    # JS digitToHex: for (i = 0; i < 4; ++i) { result += hexToChar[n & mask]; n >>>= 4; } return RSAUtils.reverseStr(result);
    # This means it takes LSB nibble first, then next, etc., and then reverses the string of 4 hex chars.
    # So, "0x1234" -> n=0x1234.
    # 1. n&0xF = 4. result="4". n=0x123.
    # 2. n&0xF = 3. result="43". n=0x12.
    # 3. n&0xF = 2. result="432". n=0x1.
    # 4. n&0xF = 1. result="4321". n=0x0.
    # reverse("4321") -> "1234". This is correct.
    for _ in range(4):
        result_chars.append(hex_chars[n_16bit_digit & 0xF])
        n_16bit_digit >>= 4
    return "".join(reversed(result_chars))


# Helper function to mimic RSAUtils.biToHex from security.js
def _python_bi_to_hex(big_int_val):
    if big_int_val == 0:
        # JS: biHighIndex(bigZero) is 0. Loop runs for i=0. digitToHex(0) is "0000".
        return "0000"

    bi_radix_bits = 16
    digits_list = []  # This will store 16-bit words, LSW first
    temp_val = big_int_val
    while temp_val > 0:
        digits_list.append(temp_val & ((1 << bi_radix_bits) - 1))  # Get LSW 16 bits
        temp_val >>= bi_radix_bits

    if not digits_list:  # Should only happen if big_int_val was 0, handled above.
        return ""  # Or raise error, but for 0 it's "0000"

    # JS biToHex iterates from biHighIndex (MSW digit) down to 0 (LSW digit)
    # and prepends the hex of each digit.
    # result = ""; for (var i = RSAUtils.biHighIndex(x); i > -1; --i) { result += RSAUtils.digitToHex(x.digits[i]); }
    # Our digits_list is LSW first (digits_list[0] is LSW).
    # So we iterate it in reverse to get MSW first.
    hex_result_parts = []
    for i in range(len(digits_list) - 1, -1, -1):  # Iterate from MSW digit down to LSW digit
        hex_result_parts.append(_python_digit_to_hex(digits_list[i]))

    final_hex = "".join(hex_result_parts)
    # RSAUtils.biToHex itself does not ensure an overall even length by prepending a single "0" to the whole string.
    # It ensures each 16-bit digit becomes 4 hex chars, so the total length is always a multiple of 4.
    return final_hex


if __name__ == "__main__":
    main()
