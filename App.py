import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 配置 ---
# 1. 设置文件上传的目标文件夹
UPLOAD_FOLDER = 'shared_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 2. 全局变量，用来追踪当前被分享的文件名
#    服务器启动时，没有任何文件被分享
CURRENT_FILENAME = None

# --- 路由 ---

@app.route('/', methods=['GET', 'POST'])
def index():
    global CURRENT_FILENAME # 声明我们要修改的是全局变量

    # 如果是 POST 请求，处理文件上传
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url) # 如果表单里没有文件部分，刷新

        file = request.files['file']

        if file.filename == '':
            return redirect(request.url) # 如果没选择文件，刷新

        if file:
            # 使用 secure_filename 防止恶意文件名
            filename = secure_filename(file.filename)
            
            # --- 核心逻辑：先删除旧文件 ---
            if CURRENT_FILENAME:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], CURRENT_FILENAME)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
            
            # 保存新文件
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # 更新全局变量，记录新的文件名
            CURRENT_FILENAME = filename
            
            return redirect(url_for('index')) # 重定向到首页，显示新的下载链接

    # 如果是 GET 请求，就显示主页
    # 把当前文件名传递给模板，让模板决定是否显示下载链接
    return render_template('index.html', filename=CURRENT_FILENAME)


@app.route('/download/<path:filename>')
def download_file(filename):
    # 使用 send_from_directory 提供安全的文件下载功能
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)