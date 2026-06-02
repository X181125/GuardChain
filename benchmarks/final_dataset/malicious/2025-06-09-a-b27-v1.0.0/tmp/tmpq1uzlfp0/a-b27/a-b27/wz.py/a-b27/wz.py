import requests

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# ASCII Art
ascii_art = f"""{GREEN}
 ___ __  __    _    ____       ____  _ _____ 
|_ _|  \/  |  / \  |  _ \     |___ \/ |___ / 
 | || |\/| | / _ \ | | | |_____ __) | | |_ \ 
 | || |  | |/ ___ \| |_| |_____/ __/| |___) |
|___|_|  |_/_/   \_\____/     |_____|_|____/ {RESET}
"""

# طباعة ASCII Art
print(ascii_art)

# طلب الـ ID من المستخدم
login_id = input("ID: ")

# إعداد الرابط والرؤوس والبيانات
url = "https://shop2game.com/api/auth/player_id_login"
headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8,ar;q=0.7",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
    "Origin": "https://shop2game.com",
    "Referer": "https://shop2game.com/?channel=246175&item=46691",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
}
cookies = {
    "source": "pc",
    "region": "DZ",
    "mspid2": "4e38c7479eb2433a82cf018cf28192f7",
    "language": "ar",
    "_ga": "GA1.1.1557196082.1742691970",
    "datadome": "eEMKyNt07cl4n05qoGGmuSUofVuGx9OWhlKDt4XfjgITRURnU2F9_szgeJ3vlMOvcfR8Xp3487iVVIrk1UHAxhxGbjokRMmet_Mzv4G2lU7VPkZxMy8WYWGNodC2YvCE",
    "session_key": "3581u8r1lbf401f91sijrenpu8clx6cw",
    "_ga_0NY2JETSPJ": "GS1.1.1742691969.1.1.1742691989.0.0.0"
}
data = {
    "app_id": 100067,
    "login_id": login_id
}

# إرسال الطلب
response = requests.post(url, headers=headers, cookies=cookies, json=data)

# معالجة الرد
if response.status_code == 200:
    # تحويل الاستجابة إلى JSON
    response_data = response.json()

    # استبعاد img_url إن وجد
    response_data.pop("img_url", None)

    # طباعة الرد بلون أخضر بشكل منظم

    for key, value in response_data.items():
        print(f"{GREEN}{key}: {value}{RESET}")
else:
    # طباعة رسالة خطأ بلون أحمر إذا فشل الطلب
    print(f"{RED}فشل الطلب. تحقق من البيانات المدخلة أو الخادم.{RESET}")
