from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops
import requests
import urllib3
import os
import csv
import time
import json
from datetime import datetime

logger = get_logger('trusguard-bulk-upload')
TMP_PATH = '/tmp/'

def upload(config, params):
    """
    TrusGuard 방화벽 블랙리스트 파일 업로드 (파일만! raw 미지원)
    params['file_iri']가 반드시 있어야 하며, 없으면 예외 발생.
    """
    trusguardip = config.get("trusguardip")
    trusguardport = config.get("trusguardport")
    BASE_URL = f"https://{trusguardip}:{trusguardport}"
    TIMEOUT = 30
    VERIFY_SSL = False
    ID = config.get("trusguardid")
    PASSWORD = config.get("trusguardpassword")
    INTERVAL_SECONDS = 600
    
    DESCRIPTION = params.get("uploaddescription", "")
                                        
    LOGIN_ATTEMPT = params.get("loginattempt")
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    def format_response_text(text):
        try:
            intermediate = json.loads(text)
            if isinstance(intermediate, str):
                parsed = json.loads(intermediate)
            else:
                parsed = intermediate
            pretty = json.dumps(parsed, ensure_ascii=False, indent=2)
            return pretty
        except Exception:
            return text

    def alert(stage, last_result):
        stage_repr = "Warning" if stage == 3 else "Retry" if stage < 5 else "Critical"
        logger.error(f"[Auth Retry {stage_repr}] {stage} consecutive failures: {last_result}")

    def authenticate():
        token_url = f"{BASE_URL}/token"
        login_url = f"{BASE_URL}/login"
        payload = {"id": ID, "password": PASSWORD}
        last_result = None

        # 기본값 5, 숫자가 아니거나 None일 경우 fallback
        max_attempt = int(LOGIN_ATTEMPT) if LOGIN_ATTEMPT and str(LOGIN_ATTEMPT).isdigit() else 5

        for attempt in range(1, max_attempt + 1):
            try:
                resp = requests.post(token_url, json=payload, verify=VERIFY_SSL, timeout=TIMEOUT)
                token_json = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else None
                token = token_json.get("token") if resp.status_code == 200 and token_json else None
            except Exception as e:
                token = None
                token_json = {"error": str(e)}
                resp = None

            if token:
                headers = {"key": "Authorization", "Authorization": token}
                try:
                    resp2 = requests.post(login_url, headers=headers, verify=VERIFY_SSL, timeout=TIMEOUT)
                    login_json = resp2.json() if resp2.headers.get('content-type', '').startswith('application/json') else None
                    login_detail = {
                        "status_code": resp2.status_code,
                        "response": login_json if resp2.status_code == 200 else resp2.text
                    }
                    if resp2.status_code == 200:
                        return token, login_json
                    else:
                        last_result = {
                            "stage": "login",
                            "attempt": attempt,
                            "resp_json": login_json,
                            "code": resp2.status_code
                        }
                except Exception as e:
                    last_result = {
                        "stage": "login_exception",
                        "attempt": attempt,
                        "error": str(e)
                    }
            else:
                last_result = {
                    "stage": "get_token",
                    "attempt": attempt,
                    "resp_json": token_json,
                    "code": getattr(resp, "status_code", None)
                }
            if attempt < max_attempt:
                time.sleep(INTERVAL_SECONDS)
        raise ConnectorError(f"Login failed after {max_attempt} attempts, {login_json}")
        
    def get_file_content():
        """
        file_iri 반드시 필요
        """
        file_iri = params.get('fileiri')
        if not file_iri:
            logger.error("No file_iri provided in params; file is required.")
            raise ConnectorError("No file_iri provided in params; artifact file must be specified.")
        try:
            dw_file_md = download_file_from_cyops(file_iri)
            file_path = os.path.join(TMP_PATH, dw_file_md['cyops_file_path'])
            with open(file_path, encoding='utf-8') as f:
                reader = csv.reader(f)
                rows = list(reader)
            return rows
        except Exception as err:
            logger.error(f"Failed to download or read artifact file: {err}")
            raise ConnectorError(f"Failed to download or read artifact file: {err}")

    def upload_file(token, rows):
        
        csv_path = os.path.join(TMP_PATH, "blacklist.csv")
        try:
            with open(csv_path, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            url = f"{BASE_URL}/policy/access_block/blacklist/bulk/upload"
            headers = {"key": "Authorization", "Authorization": token}
            with open(csv_path, "rb") as f:
                files = {"blacklist_csv": (csv_path, f, "text/csv")}
                resp = requests.post(url, headers=headers, files=files, timeout=TIMEOUT, verify=VERIFY_SSL)
                resp_text_raw = resp.text
                resp_text_pretty = format_response_text(resp_text_raw)
            out = {"response_code": resp.status_code, "response_text": resp_text_pretty}
            try:
                out["response"] = resp.json()
            except Exception:
                out["response"] = None
            return resp.status_code == 200, out
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    def bulk(token):
        url = f"{BASE_URL}/policy/access_block/blacklist/bulk"
        headers = {"Content-Type": "application/json", "Authorization": token}
        payload = {"description": DESCRIPTION, "expire_enable": "0"}
        resp = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT, verify=VERIFY_SSL)
        resp_text_raw = resp.text
        resp_text_pretty = format_response_text(resp_text_raw)        
        out = {"response_code": resp.status_code, "response_text": resp_text_pretty}
        try:
            out["response"] = resp.json()
        except Exception:
            out["response"] = None
        return out
    def logout(token):
        logout_url = f"{BASE_URL}/logout"
        headers = {"Authorization": token}
        try:
            response = requests.post(logout_url, headers=headers, verify=VERIFY_SSL, timeout=5)
            if response.status_code == 200:
                payload = response.json() if response.headers.get("content-type","").startswith("application/json") else response.text
                result = {"response_code": response.status_code, "response": payload}
            else:
                result = {"response_code": response.status_code, "response": response.text}
        except requests.exceptions.RequestException as e:
            result = {"response_code": None, "response": str(e)}
        return result  

  
    try:
        token, login_detail = authenticate()
        rows = get_file_content()
        up_ok, up_detail = upload_file(token, rows)
        if not up_ok:
            raise ConnectorError(f"File upload failed: {up_detail}")
        bulk_out = bulk(token)
        if bulk_out.get("response_code") != 200:
            raise ConnectorError(f"Bulk apply failed: {bulk_out}")
        
        logout_result = logout(token) if token else None
        
        return {
            "success": True,
            "login_detail": login_detail,
            "upload_detail": up_detail,
            "bulk_detail": bulk_out,
            "logout_detail": logout_result
        }
    except Exception as err:
        logger.error("Upload failed: {}".format(str(err)))
        return {
            "success": False,
            "error": str(err)
        }
