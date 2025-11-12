import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

# 1. 初始化 Flask 应用
app = Flask(__name__)

# --- 核心配置区 ---

# 2. 设置 SECRET_KEY (用于保护 session)
#    请务必替换成一个你自己的、复杂的、保密的字符串！
app.secret_key = 'qazplm714119'

# 3. 设置管理员密码
ADMIN_PASSWORD = '333222111' # <-- 在这里修改你的登录密码

# 4. 文件上传的目标文件夹
UPLOAD_FOLDER = 'shared_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 5. 用于追踪登录失败尝试的配置和全局变量
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 10
LOCKOUT_MINUTES = 30

# 6. 全局变量，用于在内存中追踪当前分享的文件名列表
CURRENT_FILENAMES = []

# --- 路由和视图函数 ---

# 主页路由 (受登录保护)
@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', filenames=CURRENT_FILENAMES)

# 文件上传路由 (受登录保护)
@app.route('/upload', methods=['POST'])
def upload_files():
    global CURRENT_FILENAMES
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    uploaded_files = request.files.getlist('file')
    if not uploaded_files or uploaded_files[0].filename == '':
        flash('未选择任何文件。', 'warning')
        return redirect(url_for('index'))
    
    # 先删除所有旧文件
    for filename in CURRENT_FILENAMES:
        old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(old_file_path):
            os.remove(old_file_path)
    
    CURRENT_FILENAMES.clear()

    # 保存所有新文件
    for file in uploaded_files:
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            CURRENT_FILENAMES.append(filename)
    
    flash('文件已成功更新！', 'success')
    return redirect(url_for('index'))

# 登录路由 (带暴力破解防御)
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    # 检查IP是否已被锁定
    if ip_address in LOGIN_ATTEMPTS and LOGIN_ATTEMPTS[ip_address]['failures'] >= MAX_ATTEMPTS:
        last_attempt_time = LOGIN_ATTEMPTS[ip_address]['last_attempt_time']
        lockout_duration = timedelta(minutes=LOCKOUT_MINUTES)
        
        if datetime.now() < last_attempt_time + lockout_duration:
            time_remaining = (last_attempt_time + lockout_duration) - datetime.now()
            minutes_remaining = (time_remaining.seconds // 60) + 1
            flash(f'登录已被锁定，请在 {minutes_remaining} 分钟后重试。', 'danger')
            return render_template('login.html')
        else:
            del LOGIN_ATTEMPTS[ip_address]

    # 处理登录表单提交
    if request.method == 'POST':
        password_attempt = request.form['password']

        if password_attempt == ADMIN_PASSWORD:
            if ip_address in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[ip_address]
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            attempt_info = LOGIN_ATTEMPTS.get(ip_address, {'failures': 0})
            attempt_info['failures'] += 1
            attempt_info['last_attempt_time'] = datetime.now()
            LOGIN_ATTEMPTS[ip_address] = attempt_info

            if attempt_info['failures'] >= MAX_ATTEMPTS:
                flash(f'尝试次数过多。您的IP已被锁定 {LOCKOUT_MINUTES} 分钟。', 'danger')
            else:
                remaining = MAX_ATTEMPTS - attempt_info['failures']
                flash(f'密码错误！您还有 {remaining} 次尝试机会。', 'danger')
            
            return render_template('login.html')
            
    return render_template('login.html')

# 登出路由
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('您已成功登出。', 'info')
    return redirect(url_for('login'))

# 文件下载路由 (保持公开)
@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# 程序入口
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)