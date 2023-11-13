import requests
from bs4 import BeautifulSoup
import sqlite3
import urllib3

# proxy server setting
proxies = {"https": "http://example.proxy.com:1234"}

# postgreSQL security page URL
postgresql_url = "https://www.postgresql.org/support/security/"

# alert url example
alert_URL = "https://example.alert.url" #CVE 알림 아지트

# SQLite DB file path
db_path = "/home/minto/cve/db/PostgreSQL_lastnews.db"

# Send notification
def send_to_agit(msg):
    header = { 'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36', 'Content-Type': 'application/json; charset=utf-8' }
    json_data = {'text': msg}
    requests.post(url=alert_URL, headers=header, json=json_data, verify=False, proxies=proxies)

def create_table(conn):
    sql = """CREATE TABLE IF NOT EXISTS cve_entries (
        id INTEGER PRIMARY KEY,
        cve TEXT,
        affected_versions TEXT,
        fixed_versions TEXT,
        cvss_score TEXT,
        link TEXT
    );"""
    conn.execute(sql)
    conn.commit()

def insert_data(conn, data):
    sql = "INSERT INTO cve_entries (cve, affected_versions, fixed_versions, cvss_score, link) VALUES (?, ?, ?, ?, ?);"
    conn.execute(sql, data)
    conn.commit()

def check_existing_cve(conn, cve):
    s_sql = "SELECT EXISTS (SELECT 1 FROM cve_entries WHERE cve = ?);"
    cursor = conn.cursor()
    cursor.execute(s_sql, (cve,))
    return cursor.fetchone()[0]

try:
    # Get web page
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Whale/3.19.166.16 Safari/537.36'}
    response = requests.get(postgresql_url, headers=headers, verify=False, proxies=proxies)
    response.raise_for_status()

    # HTML parsing
    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract the data you need
    table = soup.find('table', class_='table table-striped')
    if table:
        # SQLite DB connect
        conn = sqlite3.connect(db_path)
        create_table(conn)

        new_cves_found = False
        msg = ""

        for tr in table.find_all('tr'):
            td_tags = tr.find_all('td')
            if len(td_tags) == 5:
                cve_a_tag = td_tags[0].find('a')
                affected_versions = td_tags[1].get_text(strip=True)
                fixed_versions = td_tags[2].get_text(strip=True)
                cvss_score_a_tag = td_tags[3].find('a')
                if cve_a_tag and cvss_score_a_tag:
                    cve_number = cve_a_tag.get_text(strip=True)
                    cvss_score = cvss_score_a_tag.get_text(strip=True)
                    if cve_number.startswith("CVE-"):
                        link = f"https://www.postgresql.org/support/security/{cve_number}"
                        data = (cve_number, affected_versions, fixed_versions, cvss_score, link)
                        if not check_existing_cve(conn, cve_number):
                            insert_data(conn, data)
                            new_cves_found = True

                            msg += f"새로 업데이트된 PostgreSQL CVE 입니다.\n\n"
                            msg += f"CVE Number: {cve_number}\n"
                            msg += f"Affected Versions: {affected_versions}\n"
                            msg += f"Fixed Versions: {fixed_versions}\n"
                            msg += f"CVSS Score: {cvss_score}\n"
                            msg += f"Link: {link}\n"
                            msg += "=" * 50 + "\n"

        conn.close()

        if new_cves_found:
            send_to_agit(msg)
        else:
            msg = "새로 업데이트된 PostgreSQL CVE가 없습니다."
            send_to_agit(msg)

except requests.exceptions.RequestException as e:
    print("웹 페이지 요청 예외 발생:", e)
except Exception as e:
    print("기타 예외 발생:", e)