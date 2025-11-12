import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 配置 ---
UPLOAD_FOLDER = 'shared_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- 关键改动 1: 从单个变量变为一个列表 ---
# 用一个列表来追踪所有当前被分享的文件
CURRENT_FILENAMES = []

# --- 路由 ---

@app.route('/', methods=['GET', 'POST'])
def index():
    global CURRENT_FILENAMES # 声明我们要修改的是全局变量

    # 如果是 POST 请求，处理文件上传
    if request.method == 'POST':
        # --- 关键改动 2: 使用 getlist 获取文件列表 ---
        # request.files['file'] 只能获取第一个文件
        # request.files.getlist('file') 可以获取所有同名 input 的文件
        uploaded_files = request.files.getlist('file')

        # 如果列表为空或只包含没有文件名的空对象，则刷新
        if not uploaded_files or uploaded_files[0].filename == '':
            return redirect(request.url)
        
        # --- 核心逻辑：先删除所有旧文件 ---
        for filename in CURRENT_FILENAMES:
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(old_file_path):
                os.remove(old_file_path)
        
        # 清空记录文件名的列表
        CURRENT_FILENAMES.clear()

        # --- 关键改动 3: 循环处理并保存新文件 ---
        for file in uploaded_files:
            if file:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # 将新文件名追加到列表中
                CURRENT_FILENAMES.append(filename)
        
        return redirect(url_for('index'))

    # 如果是 GET 请求，就显示主页
    # --- 关键改动 4: 将整个列表传递给模板 ---
    return render_template('index.html', filenames=CURRENT_FILENAMES)


@app.route('/download/<path:filename>')
def download_file(filename):
    # 这个下载路由不需要任何改动，因为它一次只处理一个文件的下载请求
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)