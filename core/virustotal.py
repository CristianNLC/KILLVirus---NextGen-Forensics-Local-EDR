import requests

def check_virustotal_hash(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return response.status_code, stats, attrs.get("last_analysis_results", {})
        return response.status_code, None, None
    except Exception as e:
        return 500, None, str(e)