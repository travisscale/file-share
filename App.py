import os
import json
from flask import (Flask, render_template, request, redirect, url_for, 
                   send_from_directory, session, flash, jsonify, abort)
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps

# 1. 初始化 Flask 应用
app = Flask(__name__)

# --- 核心配置区 ---

app.secret_key = 'qazplm714119_a_much_more_secure_key'
# 新增：解决 jsonify 中文编码问题
app.config['JSON_AS_ASCII'] = False

USER_PASSWORD = '123456'
ADMIN_PASSWORD = 'qazplm714119'
UPLOAD_FOLDER = 'shared_files'
METADATA_FILE = 'file_metadata.json'
BANNED_IPS_FILE = 'banned_ips.json'
# 新增：活动日志文件
ACTIVITY_LOG_FILE = 'activity_log.json'

if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 10
LOCKOUT_MINUTES = 30

# --- 辅助函数 ---

def load_json_file(filepath, default_value):
    """通用加载JSON文件的函数"""
    if not os.path.exists(filepath): return default_value
    try:
        with open(filepath, 'r', encoding='utf-8') as f: return json.load(f)
    except (json.JSONDecodeError, IOError): return default_value

def save_json_file(filepath, data):
    """通用保存JSON文件的函数"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def log_activity(event, **details):
    """记录活动到日志文件"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "ip_address": request.headers.get('X-Forwarded-For', request.remote_addr),
        "details": details
    }
    logs = load_json_file(ACTIVITY_LOG_FILE, [])
    logs.insert(0, log_entry) # 插入到最前面，方便查看最新日志
    save_json_file(ACTIVITY_LOG_FILE, logs)

def format_filesize(size_bytes):
    """将字节大小格式化为易读的字符串"""
    if size_bytes == 0: return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

# --- IP黑名单检查 ---
@app.before_request
def check_for_banned_ip():
    banned_ips = load_json_file(BANNED_IPS_FILE, [])
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address in banned_ips: abort(403)

# --- 后台定时任务 (已修改逻辑) ---
def cleanup_old_files():
    """修改：清理超过30分钟未被访问且非永久的文件"""
    with app.app_context():
        metadata = load_json_file(METADATA_FILE, [])
        current_time = datetime.now()
        files_to_keep = []
        
        for file_info in metadata:
            is_permanent = file_info.get('permanent', False)
            # 修改：使用 last_accessed_time 进行判断
            last_accessed = datetime.fromisoformat(file_info.get('last_accessed_time', file_info['upload_time']))
            
            # 如果文件是永久的，或者距离上次访问不足30分钟，则保留
            if is_permanent or (current_time - last_accessed) < timedelta(minutes=30):
                files_to_keep.append(file_info)
            else:
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
                    if os.path.exists(file_path): os.remove(file_path)
                    print(f"Deleted expired file: {file_info['original_filename']}")
                except Exception as e:
                    print(f"Error deleting file {file_info.get('filename', 'unknown')}: {e}")

        save_json_file(METADATA_FILE, files_to_keep)

scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_old_files, trigger="interval", minutes=1)
scheduler.start()


# --- 路由 ---

@app.route('/')
def index():
    if session.get('auth_level') not in ['user', 'admin']: return redirect(url_for('login'))
    # ... (此函数的筛选逻辑保持不变) ...
    all_files_metadata = load_json_file(METADATA_FILE, [])
    # ... (筛选代码省略，与之前版本相同) ...
    uploader_filter = request.args.get('uploader', '')
    status_filter = request.args.get('status', '')
    sort_by_time = request.args.get('sort_by_time', 'newest')
    remarks_search = request.args.get('remarks_search', '')
    filename_search = request.args.get('filename_search', '')
    filtered_files = all_files_metadata[:]
    if uploader_filter: filtered_files = [f for f in filtered_files if f.get('uploader') == uploader_filter]
    if status_filter:
        is_permanent_filter = (status_filter == 'permanent')
        filtered_files = [f for f in filtered_files if f.get('permanent', False) == is_permanent_filter]
    if remarks_search: filtered_files = [f for f in filtered_files if remarks_search.lower() in f.get('remarks', '').lower()]
    if filename_search: filtered_files = [f for f in filtered_files if filename_search.lower() in f.get('original_filename', '').lower()]
    if sort_by_time == 'oldest': filtered_files.sort(key=lambda f: datetime.fromisoformat(f['upload_time']))
    else: filtered_files.sort(key=lambda f: datetime.fromisoformat(f['upload_time']), reverse=True)
    unique_uploaders = sorted(list(set(f.get('uploader', '匿名') for f in all_files_metadata)))
    for f in filtered_files: f['upload_time_str'] = datetime.fromisoformat(f['upload_time']).strftime('%Y-%m-%d %H:%M:%S')
    current_filters = {'uploader': uploader_filter, 'status': status_filter, 'sort_by_time': sort_by_time, 'remarks_search': remarks_search, 'filename_search': filename_search}
    return render_template('index.html', files=filtered_files, unique_uploaders=unique_uploaders, current_filters=current_filters)


@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    # ... (防暴力破解逻辑保持不变) ...
    if ip_address in LOGIN_ATTEMPTS and LOGIN_ATTEMPTS[ip_address]['failures'] >= MAX_ATTEMPTS:
        # ...
        last_attempt_time = LOGIN_ATTEMPTS[ip_address]['last_attempt_time']
        lockout_duration = timedelta(minutes=LOCKOUT_MINUTES)
        if datetime.now() < last_attempt_time + lockout_duration:
            time_remaining = (last_attempt_time + lockout_duration) - datetime.now()
            minutes_remaining = (time_remaining.seconds // 60) + 1
            flash(f'登录已被锁定，请在 {minutes_remaining} 分钟后重试。', 'danger')
            return render_template('login.html')
        else:
            del LOGIN_ATTEMPTS[ip_address]

    if request.method == 'POST':
        if request.form['password'] == USER_PASSWORD:
            if ip_address in LOGIN_ATTEMPTS: del LOGIN_ATTEMPTS[ip_address]
            session['auth_level'] = 'user'
            # 新增：记录登录活动
            log_activity('user_login_success')
            return redirect(url_for('index'))
        else:
            # ... (登录失败处理逻辑保持不变) ...
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

@app.route('/upload', methods=['POST'])
def upload_files():
    if session.get('auth_level') not in ['user', 'admin']:
        return jsonify({'error': '用户未登录'}), 401
    
    uploaded_files = request.files.getlist('file')
    uploader = request.form.get('uploader', '').strip() or '匿名'
    remarks = request.form.get('remarks', '').strip() or '无'
    
    if not uploaded_files or not uploaded_files[0].filename:
        return jsonify({'error': '未选择任何文件'}), 400
    
    metadata = load_json_file(METADATA_FILE, [])
    try:
        now_iso = datetime.now().isoformat()
        for file in uploaded_files:
            if file and file.filename:
                # --- 这是本次修改的核心 ---
                # 保存真实的原始文件名
                original_filename = file.filename
                # 创建一个安全的文件名用于存储
                safe_filename_base = secure_filename(original_filename)
                unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{safe_filename_base}"
                # -------------------------

                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                
                file_size = os.path.getsize(filepath)

                file_info = {
                    'filename': unique_filename,
                    # 修改：确保保存的是未经处理的原始文件名
                    'original_filename': original_filename, 
                    'uploader': uploader,
                    'remarks': remarks,
                    'upload_time': now_iso,
                    'last_accessed_time': now_iso,
                    'size': file_size,
                    'permanent': False
                }
                metadata.append(file_info)
                log_activity('file_upload', uploader=uploader, filename=original_filename, size=format_filesize(file_size))
        
        save_json_file(METADATA_FILE, metadata)
        return jsonify({'success': '文件已成功上传！'})
    except Exception as e:
        # 打印详细错误到控制台，方便调试
        print(f"Upload error: {e}")
        return jsonify({'error': f'文件上传失败: {str(e)}'}), 500

@app.route('/download/<path:filename>')
def download_file(filename):
    if session.get('auth_level') not in ['user', 'admin']: return redirect(url_for('login'))
    
    metadata = load_json_file(METADATA_FILE, [])
    file_found = False
    original_filename = filename
    
    for file_info in metadata:
        if file_info['filename'] == filename:
            # 修改：更新最后访问时间以重置30分钟计时器
            file_info['last_accessed_time'] = datetime.now().isoformat()
            original_filename = file_info['original_filename']
            file_found = True
            break
            
    if file_found:
        save_json_file(METADATA_FILE, metadata)
        # 新增：记录下载活动
        log_activity('file_download', filename=original_filename)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, download_name=original_filename)

# --- 管理员功能 (admin_login, logout, require_admin 等保持不变) ---
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session['auth_level'] = 'admin'
            log_activity('admin_login_success') # 记录管理员登录
            flash('管理员登录成功！', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('管理员密码错误！', 'danger')
            return redirect(url_for('admin_login'))
    if session.get('auth_level') == 'admin': return redirect(url_for('admin_panel'))
    if session.get('auth_level') != 'user':
        flash('请先完成常规登录。', 'info')
        return redirect(url_for('login'))
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.pop('auth_level', None)
    flash('您已成功登出。', 'info')
    return redirect(url_for('login'))

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('auth_level') != 'admin':
            flash('此操作需要管理员权限。', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- 管理面板路由 (已修改) ---
@app.route('/admin')
@require_admin
def admin_panel():
    all_files = load_json_file(METADATA_FILE, [])
    for f in all_files:
        f['upload_time_str'] = datetime.fromisoformat(f['upload_time']).strftime('%Y-%m-%d %H:%M:%S')
        # 新增：格式化文件大小
        f['formatted_size'] = format_filesize(f.get('size', 0))
    
    banned_ips = load_json_file(BANNED_IPS_FILE, [])
    # 新增：加载活动日志，并只取最近100条以防页面过大
    activity_log = load_json_file(ACTIVITY_LOG_FILE, [])[:100]

    return render_template('admin.html', files=all_files, banned_ips=banned_ips, 
                           login_attempts=LOGIN_ATTEMPTS, activity_log=activity_log)

# ... (delete_file, toggle_status, ban_ip, unban_ip 路由保持不变) ...
@app.route('/delete/<path:filename>', methods=['POST'])
@require_admin
def delete_file(filename):
    metadata = load_json_file(METADATA_FILE, [])
    file_to_delete = next((f for f in metadata if f['filename'] == filename), None)
    if file_to_delete:
        metadata.remove(file_to_delete)
        save_json_file(METADATA_FILE, metadata)
        try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        except OSError: pass
        log_activity('file_delete_admin', filename=file_to_delete['original_filename'])
        flash(f"文件 '{file_to_delete['original_filename']}' 已被删除。", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/toggle_status/<path:filename>', methods=['POST'])
@require_admin
def toggle_status(filename):
    metadata = load_json_file(METADATA_FILE, [])
    for file_info in metadata:
        if file_info['filename'] == filename:
            new_status = not file_info.get('permanent', False)
            file_info['permanent'] = new_status
            save_json_file(METADATA_FILE, metadata)
            log_activity('status_toggle_admin', filename=file_info['original_filename'], new_status='permanent' if new_status else 'temporary')
            flash(f"文件 '{file_info['original_filename']}' 的状态已更新。", 'success')
            break
    return redirect(url_for('admin_panel'))

@app.route('/ban_ip', methods=['POST'])
@require_admin
def ban_ip():
    ip_to_ban = request.form.get('ip_to_ban')
    if ip_to_ban:
        banned_ips = load_json_file(BANNED_IPS_FILE, [])
        if ip_to_ban not in banned_ips:
            banned_ips.append(ip_to_ban)
            save_json_file(BANNED_IPS_FILE, banned_ips)
            log_activity('ip_ban_admin', banned_ip=ip_to_ban)
            flash(f"IP地址 {ip_to_ban} 已被封禁。", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/unban_ip', methods=['POST'])
@require_admin
def unban_ip():
    ip_to_unban = request.form.get('ip_to_unban')
    if ip_to_unban:
        banned_ips = load_json_file(BANNED_IPS_FILE, [])
        if ip_to_unban in banned_ips:
            banned_ips.remove(ip_to_unban)
            save_json_file(BANNED_IPS_FILE, banned_ips)
            log_activity('ip_unban_admin', unbanned_ip=ip_to_unban)
            flash(f"IP地址 {ip_to_unban} 已被解封。", 'success')
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)