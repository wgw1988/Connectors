from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops
import requests
import urllib3
import csv
import os
import tempfile
import re
import time
from datetime import datetime

logger = get_logger("trusguard-bulk-connector")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TMP_DIR = tempfile.gettempdir()

def delete_merge(config, params):

    trusguardip = config.get("trusguardip")
    trusguardport = config.get("trusguardport")
    BASE_URL = f"https://{trusguardip}:{trusguardport}"
    TIMEOUT = 30
    VERIFY_SSL = False
    ID = config.get("trusguardid")
    PASSWORD = config.get("trusguardpassword")
    INTERVAL_SECONDS = 600

    DELETE_DESCRIPTION = params.get("deletedescription", "")
    MERGE_DESCRIPTION = params.get("mergedescription", "")
    
    END_DATE = params.get("enddate")
    FILE_IRIS = params.get("fileiris", [])
    LOGIN_ATTEMPT = params.get("loginattempt")
    TOKEN = None

    if not END_DATE:
        raise ConnectorError("Parameter 'end_date' is required.")
    if not FILE_IRIS:
        raise ConnectorError("Parameter 'file_iris' list is required.")

    def download_and_merge(fileiris):
        merged_rows = []
        for file_iri in fileiris:
            rows = get_file_content(file_iri)
            merged_rows.extend(rows)
        return merged_rows

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
        
    def search_indices(base_url, description, timeout, verify_ssl):
        url = f"{base_url}/policy/access_block/blacklist/bulk/search"
        headers = {
            "Content-Type": "application/json",
            "Authorization": TOKEN
        }
        resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
        try:
            response_json = resp.json()
        except Exception:
            response_json = resp.text

        if resp.status_code == 200:
            indices = [item['index'] for item in response_json.get('result', [])] \
                if isinstance(response_json, dict) else []
            logger.info(f"Search success: {response_json}")
            return indices, response_json
        else:
            logger.error(f"Search failed: {response_json}")
            return [], response_json


    def filter_by_date_and_description(results, end_date, delete_description):
        import re
        from datetime import datetime
    
        s = str(end_date)
        if '-' in s:
            s = datetime.strptime(s, "%Y-%m-%d").strftime("%Y%m%d")
        elif re.fullmatch(r"\d{6}", s):
            s = "20" + s
        elif not re.fullmatch(r"\d{8}", s):
            raise ValueError(f"Invalid end_date: {s}")
    
        start = s[:6] + "01"
        logger.debug(f"Filtering from {start} to {s}, desc contains '{delete_description}'")
    
        matched = []
        for item in results:
            fn = item.get("file_name")
            desc = item.get("description")
            logger.debug(f"Checking item index={item.get('index')}, file_name={fn}, description={desc}")
    
            m = re.search(r"(\d{8})", fn or "")
            if not m:
                logger.debug("  → no date in file_name")
                continue
            file_date = m.group(1)
            logger.debug(f"  → extracted date {file_date}")
    
            if not (start <= file_date <= s):
                logger.debug("  → date out of range")
                continue
    
            if delete_description.lower() not in (desc or "").lower():
                logger.debug("  → description does not match")
                continue
    
            logger.debug("  → matched!")
            matched.append(item)
    
        logger.debug(f"Filtered items: {matched}")
        return matched



    def delete_indices(indices):
        url = f"{BASE_URL}/policy/access_block/blacklist/bulk"
        headers = {"Content-Type": "application/json", "Authorization": TOKEN}
        normalized = sorted({int(i) for i in indices}, reverse=True)
        logger.debug(f"Deleting indices: {normalized}")
        responses = []
        for idx in normalized:
            payload = {"index": str(idx)}
            logger.debug(f"DELETE URL: {url}, payload: {payload}")
            resp = requests.delete(url, headers=headers, json=payload,
                                   timeout=TIMEOUT, verify=VERIFY_SSL)
            try:
                content = resp.json()
            except Exception:
                content = resp.text
            logger.debug(f"DELETE response idx={idx}: {resp.status_code}, {content}")
            responses.append({"index": idx, "status_code": resp.status_code, "response": content})
        return responses
      
    def get_file_content(file_iri):
        try:
            dw_file_md = download_file_from_cyops(file_iri)
            file_path = os.path.join(TMP_DIR, dw_file_md['cyops_file_path'])
            with open(file_path, encoding='utf-8') as f:
                reader = csv.reader(f)
                rows = list(reader)
            try:
                os.remove(file_path)
            except Exception:
                pass
            return rows
        except Exception as err:
            logger.error(f"Failed to download or read artifact file '{file_iri}': {err}")
            raise ConnectorError(f"Failed to download or read artifact file '{file_iri}': {err}")

    def upload_file(rows):
        csv_path = os.path.join(TMP_DIR, "merged_blacklist.csv")
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            url = f"{BASE_URL}/policy/access_block/blacklist/bulk/upload"
            up_headers = {"key": "Authorization", "Authorization": TOKEN}
            with open(csv_path, "rb") as f:
                files = {"blacklist_csv": (csv_path, f, "text/csv")}
                resp = requests.post(url, headers=up_headers, files=files, timeout=TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                try:
                    return True, resp.json()
                except Exception:
                    return True, resp.text
            else:
                return False, resp.text
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    def call_bulk():
        url = f"{BASE_URL}/policy/access_block/blacklist/bulk"
        headers = {"Content-Type": "application/json", "Authorization": TOKEN}
        payload = {"description": MERGE_DESCRIPTION, "expire_enable": "0"}
        resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=VERIFY_SSL)
        if resp.status_code == 200:
            try:
                return True, resp.json()
            except Exception:
                return True, resp.text
        else:
            return False, resp.text

    try:
        TOKEN, login_detail = authenticate()
        logger.info(f"Login detail: {login_detail}")

        # 파일 병합
        merged_rows = download_and_merge(FILE_IRIS)
        if not merged_rows:
            raise ConnectorError("No merged data found in merge files.")

        # 업로드
        upload_ok, upload_resp = upload_file(merged_rows)
        if not upload_ok:
            raise ConnectorError(f"File upload failed: {upload_resp}")
            
        # 1) 검색
        indices, resp_json = search_indices(BASE_URL, DELETE_DESCRIPTION, TIMEOUT, VERIFY_SSL)
        raw_results = resp_json.get("result", []) if isinstance(resp_json, dict) else []


        # 2) 필터링
        filtered_items = filter_by_date_and_description(raw_results, END_DATE, DELETE_DESCRIPTION)
        indices_to_delete = [item["index"] for item in filtered_items]
        logger.info(f"1일부터 '{END_DATE}'까지, description '{DELETE_DESCRIPTION}' 일치 인덱스: {indices_to_delete}")

        # 3) 삭제
        delete_responses = delete_indices(indices_to_delete)
        for resp in delete_responses:
            print(f"Index {resp['index']} 삭제 상태: {resp['status_code']}, 응답: {resp['response']}")
        
        # bulk 호출
        bulk_ok, bulk_resp = call_bulk()
        if not bulk_ok:
            raise ConnectorError(f"Bulk apply failed: {bulk_resp}")

        logger.info(f"Deleted indices response details: {delete_responses}")

        return {
            "success": True,
            "login_detail": login_detail,
            "deleted_response": {
                "response_json": resp_json,
                "description": DELETE_DESCRIPTION,
                "delete_results": delete_responses
            },
            "upload_response": upload_resp,
            "bulk_response": bulk_resp
        }

    except Exception as e:
        logger.error(f"delete_merge failed: {str(e)}")
        return {"success": False, "error": str(e)}
