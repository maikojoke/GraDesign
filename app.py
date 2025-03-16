# 导入必要的 Python 模块
from flask import Flask, render_template, request, redirect, url_for, session, send_file  # Flask 框架相关模块
from flask_bcrypt import Bcrypt  # 用于密码哈希加密
import pymysql  # 用于连接和管理 MySQL 数据库
import logging  # 用于记录日志
import re  # 正则表达式模块，用于解析表名等
from datetime import datetime  # 处理日期和时间
import io  # 处理文件流
import os  # 与操作系统交互，例如获取环境变量

# 创建 Flask 应用实例
app = Flask(__name__)
# 设置 Flask 的密钥，用于会话管理，从环境变量获取，若无则使用默认值
app.secret_key = os.getenv('SECRET_KEY', 'my_secret_key_here')
# 初始化 Bcrypt，用于密码加密
bcrypt = Bcrypt(app)

# 配置日志记录，设置日志级别为 INFO，定义日志格式包括时间、级别和消息
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义连接 dbtest 数据库的函数
def get_dbtest_connection():
    try:
        # 尝试建立与 dbtest 数据库的连接
        return pymysql.connect(
            host='localhost',  # 数据库主机地址
            user='root',  # 数据库用户名
            password=os.getenv('DB_PASSWORD', '123456'),  # 密码从环境变量获取，默认 '123456'
            database='dbtest',  # 目标数据库名
            cursorclass=pymysql.cursors.DictCursor  # 返回结果为字典格式
        )
    except pymysql.Error as e:
        # 如果连接失败，记录错误日志并返回 None
        logging.error(f"dbtest 数据库连接失败: {e}")
        return None

# 定义连接 daily_data 数据库的函数
def get_daily_data_connection():
    try:
        # 尝试建立与 daily_data 数据库的连接
        return pymysql.connect(
            host='localhost',  # 数据库主机地址
            user='root',  # 数据库用户名
            password=os.getenv('DB_PASSWORD', '123456'),  # 密码从环境变量获取，默认 '123456'
            database='daily_data',  # 目标数据库名
            cursorclass=pymysql.cursors.DictCursor  # 返回结果为字典格式
        )
    except pymysql.Error as e:
        # 如果连接失败，记录错误日志并返回 None
        logging.error(f"daily_data 数据库连接失败: {e}")
        return None

# 定义登录路由，支持 GET 和 POST 方法
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # 如果是 POST 请求，表示用户提交了登录表单
        username = request.form['username']  # 从表单获取用户名
        password = request.form['password']  # 从表单获取密码

        # 尝试用户登录（users 表）
        conn = get_dbtest_connection()  # 获取数据库连接
        if not conn:  # 如果连接失败，返回错误页面
            return render_template('error.html', message='数据库连接失败')
        cursor = conn.cursor()  # 创建数据库游标
        # 查询 users 表中是否存在该用户名
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()  # 获取查询结果

        if user:  # 如果找到用户
            stored_password = user['password']  # 获取数据库中存储的密码
            if bcrypt.check_password_hash(stored_password, password):  # 验证密码是否匹配
                session['user_id'] = user['id']  # 将用户 ID 存入会话
                logging.info(f"用户 {username} 登录成功 (bcrypt)")  # 记录登录成功日志
                conn.close()  # 关闭数据库连接
                return redirect(url_for('profile'))  # 重定向到个人页面
        else:  # 如果普通用户不存在，尝试签约医师登录（physicians 表）
            cursor.execute('SELECT * FROM physicians WHERE username = %s', (username,))
            physician = cursor.fetchone()  # 获取查询结果
            if physician:  # 如果找到签约医师
                stored_password = physician['password']  # 获取存储的密码
                if bcrypt.check_password_hash(stored_password, password):  # 验证密码是否匹配
                    session['physician_id'] = physician['id']  # 将医师 ID 存入会话
                    logging.info(f"签约医师 {username} 登录成功 (bcrypt)")  # 记录登录成功日志
                    conn.close()  # 关闭数据库连接
                    return redirect(url_for('physician'))  # 重定向到医师页面

        # 如果登录失败
        logging.warning(f"用户 {username} 登录失败")  # 记录登录失败日志
        conn.close()  # 关闭数据库连接
        return render_template('login.html', error='用户名或密码错误')  # 返回登录页面并显示错误信息
    return render_template('login.html')  # 如果是 GET 请求，显示登录页面

# 定义注册路由，支持 GET 和 POST 方法
@app.route('/register', methods=['GET', 'POST'])
def register():
    """处理用户注册请求，支持普通用户和签约医师"""
    if request.method == 'POST':  # POST 请求，用户提交注册表单
        username = request.form['username']  # 获取用户名
        password = request.form['password']  # 获取密码
        confirm_password = request.form['confirm_password']  # 获取确认密码
        user_type = request.form.get('user_type', 'user')  # 获取用户类型，默认普通用户

        if password != confirm_password:  # 检查密码是否一致
            return render_template('register.html', error='两次输入的密码不一致')

        if user_type == 'physician' and not username.startswith('doctor_'):  # 检查医师用户名格式
            return render_template('register.html', error='签约医师用户名必须以 "doctor_" 开头')

        conn = get_dbtest_connection()  # 连接数据库
        if not conn:  # 连接失败返回错误页面
            return render_template('error.html', message='数据库连接失败')
        cursor = conn.cursor()  # 创建游标

        try:
            table = 'physicians' if user_type == 'physician' else 'users'  # 根据类型选表
            cursor.execute(f'SELECT COUNT(*) as count FROM {table} WHERE username = %s', (username,))  # 查询用户名是否存在
            if cursor.fetchone()['count'] > 0:
                conn.close()
                return render_template('register.html', error=f'用户名 "{username}" 已存在，请选择其他用户名')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # 加密密码
            if user_type == 'physician':
                cursor.execute('INSERT INTO physicians (username, password) VALUES (%s, %s)',(username, hashed_password))  # 插入医师记录
                session['physician_id'] = cursor.lastrowid  # 存医师 ID 到 session
                logging.info(f"签约医师 {username} 注册并登录成功, 类型: {user_type}")  # 记录成功日志
                conn.commit()
                conn.close()
                return redirect(url_for('physician'))  # 重定向到医师页面
            else:
                cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)',(username, hashed_password))  # 插入用户记录
                session['user_id'] = cursor.lastrowid  # 存用户 ID 到 session
                logging.info(f"用户 {username} 注册并登录成功, 类型: {user_type}")  # 记录成功日志
                conn.commit()
                conn.close()
                return redirect(url_for('profile'))  # 重定向到个人页面
        except pymysql.Error as e:
            conn.rollback()  # 出错时回滚
            logging.error(f"注册失败: {e}")  # 记录错误日志
            conn.close()
            return render_template('register.html', error=f'注册失败: {str(e)}')

    return render_template('register.html')  # GET 请求返回注册页面


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='dbtest 数据库连接失败')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))
    username = cursor.fetchone()['username']
    conn.close()
    if username.startswith('doctor_'):
        return redirect(url_for('login'))

    conn_dbtest = get_dbtest_connection()
    if not conn_dbtest:
        return render_template('error.html', message='dbtest 数据库连接失败')
    cursor_dbtest = conn_dbtest.cursor()

    if request.method == 'POST':
        try:
            health_conditions = request.form['health_conditions']
            if health_conditions == '其他':
                health_conditions = request.form.get('other_health_conditions', '未知')

            # 添加区域字段
            profile_data = (
                request.form['username'], request.form['gender'],
                request.form.get('age', type=int), request.form['phone'], request.form['address'],
                request.form['birth_date'] or None, request.form['emergency_contact'],
                request.form['emergency_phone'], health_conditions,
                request.form['province'], request.form['city'], request.form['district'],  # 新增区域字段
                session['user_id']
            )
            cursor_dbtest.execute('SELECT COUNT(*) as count FROM user_profile WHERE user_id = %s',
                                  (session['user_id'],))
            result = cursor_dbtest.fetchone()
            if result['count'] > 0:
                cursor_dbtest.execute('''
                    UPDATE user_profile 
                    SET username = %s, gender = %s, age = %s, phone = %s, address = %s, 
                        birth_date = %s, emergency_contact = %s, emergency_phone = %s, 
                        health_conditions = %s, province = %s, city = %s, district = %s
                    WHERE user_id = %s
                ''', profile_data)
            else:
                cursor_dbtest.execute('''
                    INSERT INTO user_profile 
                    (username, gender, age, phone, address, birth_date, emergency_contact, 
                     emergency_phone, health_conditions, province, city, district, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', profile_data)
            conn_dbtest.commit()
            logging.info(f"用户 {session['user_id']} 更新个人信息成功")
        except pymysql.Error as e:
            conn_dbtest.rollback()
            logging.error(f"个人信息更新失败: {e}")

    cursor_dbtest.execute('SELECT * FROM user_profile WHERE user_id = %s', (session['user_id'],))
    profile = cursor_dbtest.fetchone()
    conn_dbtest.close()

    # 只保留广东省和江门市相关数据
    provinces = ['广东省']  # 仅广东省
    cities = {
        '广东省': ['江门市']  # 仅江门市
    }
    districts = {
        '江门市': [
            '蓬江区', '江海区', '新会区',  # 江门市辖区
            '台山市', '开平市', '鹤山市', '恩平市'  # 江门市代管的县级市
        ]
    }

    return render_template('profile.html', profile=profile,
                           emergency_link=url_for('emergency'),
                           consultation_link=url_for('health_consultation'),
                           health_info_link=url_for('health_info'),
                           health_knowledge_link=url_for('health_knowledge'),
                           provinces=provinces, cities=cities, districts=districts)

# 定义签约医师页面路由，支持 GET 和 POST 方法
@app.route('/physician', methods=['GET', 'POST'])
def physician():
    if 'physician_id' not in session:  # 如果医师未登录
        return redirect(url_for('login'))  # 重定向到登录页面

    conn = get_dbtest_connection()  # 获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标

    try:
        # 查询所有用户的个人信息，按用户名排序
        cursor.execute('SELECT * FROM user_profile ORDER BY username')
        users = cursor.fetchall()  # 获取所有用户信息

        # 查询所有健康咨询记录，包括提问用户和回复医师的信息
        cursor.execute('''
            SELECT hc.id, hc.question, hc.answer, hc.created_at, hc.answered_at, u.username AS user_username, p.username AS physician_username
            FROM health_consultations hc
            JOIN users u ON hc.user_id = u.id
            LEFT JOIN physicians p ON hc.physician_id = p.id
            ORDER BY hc.created_at DESC
        ''')
        consultations = cursor.fetchall()  # 获取所有健康咨询记录
        logging.debug(f"查询到的用户: {users}")  # 记录调试日志
        logging.debug(f"查询到的健康质询: {consultations}")  # 记录调试日志

        if request.method == 'POST':  # 如果是 POST 请求，表示医师提交了健康咨询回复
            consultation_id = request.form.get('consultation_id')  # 获取咨询 ID
            answer = request.form.get('answer')  # 获取回复内容
            if consultation_id and answer:  # 如果提供了 ID 和回复内容
                try:
                    # 更新健康咨询记录，添加回复、医师 ID 和回复时间
                    cursor.execute('''
                        UPDATE health_consultations 
                        SET answer = %s, physician_id = %s, answered_at = NOW()
                        WHERE id = %s
                    ''', (answer, session['physician_id'], consultation_id))
                    conn.commit()  # 提交数据库更改
                    logging.info(f"签约医师 {session['physician_id']} 回复健康质询 {consultation_id}")  # 记录回复成功日志
                except pymysql.Error as e:  # 如果数据库操作失败
                    conn.rollback()  # 回滚事务
                    logging.error(f"回复健康质询失败: {e}")  # 记录错误日志

        # 再次查询更新后的健康咨询数据
        cursor.execute('''
            SELECT hc.id, hc.question, hc.answer, hc.created_at, hc.answered_at, u.username AS user_username, p.username AS physician_username
            FROM health_consultations hc
            JOIN users u ON hc.user_id = u.id
            LEFT JOIN physicians p ON hc.physician_id = p.id
            ORDER BY hc.created_at DESC
        ''')
        consultations = cursor.fetchall()  # 获取更新后的咨询记录

        logging.info(f"签约医师查看用户列表和健康质询，用户数量: {len(users)}, 质询数量: {len(consultations)}")
        # 记录查看日志
    except pymysql.Error as e:  # 如果查询失败
        logging.error(f"查询用户或健康质询失败: {e}")  # 记录错误日志
        users = []  # 返回空用户列表
        consultations = []  # 返回空咨询列表
    finally:
        conn.close()  # 关闭数据库连接

    # 渲染医师页面模板，传递用户信息和健康咨询数据
    return render_template('physician.html', users=users, consultations=consultations)


@app.route('/disease_prediction')
def disease_prediction():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check if the user is a regular user (not a physician)
    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='dbtest 数据库连接失败')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))
    username = cursor.fetchone()['username']
    conn.close()
    if username.startswith('doctor_'):
        return redirect(url_for('login'))

    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()

    # Query user profile
    cursor.execute('SELECT * FROM user_profile WHERE user_id = %s', (session['user_id'],))
    profile = cursor.fetchone()

    # Query medical records
    cursor.execute('SELECT id, file_name, upload_date FROM medical_records WHERE user_id = %s', (session['user_id'],))
    medical_records = cursor.fetchall()

    # Query emergency events
    cursor.execute('SELECT * FROM emergency_events WHERE user_id = %s ORDER BY created_at DESC', (session['user_id'],))
    emergency_events = cursor.fetchall()

    health_data = get_latest_health_data(session['user_id'])  # 获取最新健康数据
    # 预测疾病风险
    prediction = predict_disease_risk(profile, health_data, medical_records, emergency_events)
    logging.info(f"预测结果: {prediction}")  # 记录预测结果日志

    conn.close()
    return render_template('disease_prediction.html', title='疾病预测', prediction=prediction)

# 定义紧急情况页面路由，支持 GET 和 POST 方法
@app.route('/emergency', methods=['GET', 'POST'])
def emergency():
    if 'user_id' not in session:  # 如果用户未登录
        return redirect(url_for('login'))  # 重定向到登录页面
    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()  # 获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='dbtest 数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))  # 查询用户名
    username = cursor.fetchone()['username']  # 获取用户名
    conn.close()  # 关闭数据库连接
    if username.startswith('doctor_'):  # 如果用户名为签约医师格式
        return redirect(url_for('login'))  # 重定向到登录页面，防止签约医师访问

    conn = get_dbtest_connection()  # 再次获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标

    # 查询用户的个人信息
    cursor.execute('SELECT * FROM user_profile WHERE user_id = %s', (session['user_id'],))
    profile = cursor.fetchone()  # 获取个人信息记录

    if request.method == 'POST' and 'medical_file' in request.files:  # 如果是 POST 请求且包含文件上传
        file = request.files['medical_file']  # 获取上传的文件
        if file and file.filename:  # 如果文件存在且有文件名
            file_name = file.filename  # 获取文件名
            file_type = file.mimetype  # 获取文件类型
            file_data = file.read()  # 读取文件数据
            try:
                # 插入文件记录到 medical_records 表
                cursor.execute('''
                    INSERT INTO medical_records (user_id, file_name, file_type, file_data)
                    VALUES (%s, %s, %s, %s)
                ''', (session['user_id'], file_name, file_type, file_data))
                conn.commit()  # 提交数据库更改
                logging.info(f"用户 {session['user_id']} 上传病历档案: {file_name}")  # 记录上传成功日志
            except pymysql.Error as e:  # 如果数据库操作失败
                conn.rollback()  # 回滚事务
                logging.error(f"文件上传失败: {e}")  # 记录错误日志

    # 查询用户的病历记录
    cursor.execute('SELECT id, file_name, upload_date FROM medical_records WHERE user_id = %s', (session['user_id'],))
    medical_records = cursor.fetchall()  # 获取所有病历记录
    # 查询用户的紧急事件记录，按创建时间倒序排序
    cursor.execute('SELECT * FROM emergency_events WHERE user_id = %s ORDER BY created_at DESC', (session['user_id'],))
    emergency_events = cursor.fetchall()  # 获取所有紧急事件记录

    health_data = get_latest_health_data(session['user_id'])  # 获取最新健康数据

    if check_health_thresholds(health_data):  # 检查健康数据是否超出阈值
        today = datetime.now().date()  # 获取当前日期
        # 检查当天是否已记录过“健康数据异常”事件
        cursor.execute('''
            SELECT COUNT(*) as count FROM emergency_events 
            WHERE user_id = %s AND event_type = %s AND DATE(event_time) = %s
        ''', (session['user_id'], '健康数据异常', today))
        result = cursor.fetchone()
        if result['count'] == 0:  # 如果当天还未记录
            # 插入新的紧急事件记录
            cursor.execute('''
                INSERT INTO emergency_events (user_id, emergency_contact, emergency_phone, event_type, event_time, event_description, past_medical_history, current_condition)
                VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
            ''', (session['user_id'], profile['emergency_contact'] if profile else '未知',
                  profile['emergency_phone'] if profile else '未知', '健康数据异常',
                  f"健康数据超出阈值: {health_data.get('alert_message', '未知异常')}",
                  profile['health_conditions'] if profile else '未知', str(health_data)))
            conn.commit()  # 提交数据库更改
            logging.info(f"用户 {session['user_id']} 触发紧急事件")  # 记录触发日志
        else:
            logging.info(f"用户 {session['user_id']} 当天已触发过紧急事件，跳过重复触发")  # 记录跳过日志

    conn.close()  # 关闭数据库连接
    # 渲染紧急情况页面模板，传递个人信息、病历记录、紧急事件和健康数据
    return render_template('emergency.html', title='紧急救援', profile=profile, medical_records=medical_records,
                           emergency_events=emergency_events, health_data=health_data)

# 定义健康信息页面路由
@app.route('/health_info')
def health_info():
    if 'user_id' not in session:  # 检查用户是否登录
        return redirect(url_for('login'))

    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))
    username = cursor.fetchone()['username']
    conn.close()
    if username.startswith('doctor_'):
        return redirect(url_for('login'))

    # 获取最新健康数据
    health_data = get_latest_health_data(session['user_id'])
    return render_template('health_info.html', health_data=health_data)


# 定义健康知识页面路由
@app.route('/health_knowledge')
def health_knowledge():
    if 'user_id' not in session:  # 检查用户是否登录
        return redirect(url_for('login'))

    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))
    username = cursor.fetchone()['username']
    conn.close()
    if username.startswith('doctor_'):
        return redirect(url_for('login'))

    return render_template('health_knowledge.html')

# 定义健康咨询页面路由，支持 GET 和 POST 方法
@app.route('/health_consultation', methods=['GET', 'POST'])
def health_consultation():
    if 'user_id' not in session:  # 如果用户未登录
        return redirect(url_for('login'))  # 重定向到登录页面
    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()  # 获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='dbtest 数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))  # 查询用户名
    username = cursor.fetchone()['username']  # 获取用户名
    conn.close()  # 关闭数据库连接
    if username.startswith('doctor_'):  # 如果用户名为签约医师格式
        return redirect(url_for('login'))  # 重定向到登录页面，防止签约医师访问

    conn = get_dbtest_connection()  # 再次获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标

    # 查询用户的个人信息
    cursor.execute('SELECT * FROM user_profile WHERE user_id = %s', (session['user_id'],))
    profile = cursor.fetchone()  # 获取个人信息记录
    # 查询用户的病历记录
    cursor.execute('SELECT id, file_name, upload_date FROM medical_records WHERE user_id = %s', (session['user_id'],))
    medical_records = cursor.fetchall()  # 获取所有病历记录
    # 查询用户的最近三条紧急事件记录
    cursor.execute('SELECT * FROM emergency_events WHERE user_id = %s ORDER BY created_at DESC LIMIT 3',
                   (session['user_id'],))
    emergency_events = cursor.fetchall()  # 获取紧急事件记录
    health_data = get_latest_health_data(session['user_id'])  # 获取最新健康数据

    consultation_response = None  # 初始化咨询回复变量
    if request.method == 'POST' and 'question' in request.form:  # 如果是 POST 请求且包含问题
        question = request.form['question']  # 获取用户提交的问题
        try:
            # 插入健康咨询记录到数据库
            cursor.execute('''
                INSERT INTO health_consultations (user_id, question)
                VALUES (%s, %s)
            ''', (session['user_id'], question))
            conn.commit()  # 提交数据库更改
            logging.info(f"用户 {session['user_id']} 提交健康质询: {question}")  # 记录提交日志
        except pymysql.Error as e:  # 如果数据库操作失败
            conn.rollback()  # 回滚事务
            logging.error(f"保存健康质询失败: {e}")  # 记录错误日志
        # 生成自动回复
        consultation_response = generate_consultation_response(question, profile, health_data, medical_records, emergency_events)
        logging.info(f"用户 {session['user_id']} 提交咨询: {question}, 回复: {consultation_response}")  # 记录回复日志

    # 查询用户的所有已回复健康咨询记录
    cursor.execute('''
        SELECT hc.question, hc.answer, hc.created_at, hc.answered_at, p.username AS physician_username
        FROM health_consultations hc
        LEFT JOIN physicians p ON hc.physician_id = p.id
        WHERE hc.user_id = %s AND hc.answer IS NOT NULL
        ORDER BY hc.answered_at DESC
    ''', (session['user_id'],))
    consultations = cursor.fetchall()  # 获取已回复的咨询记录

    conn.close()  # 关闭数据库连接
    # 渲染健康咨询页面模板，传递个人信息、健康数据、病历记录、紧急事件、自动回复和历史咨询
    return render_template('health_consultation.html', profile=profile, health_data=health_data,
                           medical_records=medical_records, emergency_events=emergency_events,
                           consultation_response=consultation_response, consultations=consultations)

# 定义下载病历文件路由
@app.route('/download_medical_record/<int:record_id>')
def download_medical_record(record_id):
    if 'user_id' not in session:  # 如果用户未登录
        return redirect(url_for('login'))  # 重定向到登录页面
    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()  # 获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='dbtest 数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))  # 查询用户名
    username = cursor.fetchone()['username']  # 获取用户名
    conn.close()  # 关闭数据库连接
    if username.startswith('doctor_'):  # 如果用户名为签约医师格式
        return redirect(url_for('login'))  # 重定向到登录页面，防止签约医师访问

    conn = get_dbtest_connection()  # 再次获取数据库连接
    if not conn:  # 如果连接失败，返回错误页面
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()  # 创建数据库游标
    # 查询指定 ID 的病历记录，确保属于当前用户
    cursor.execute('SELECT file_name, file_type, file_data FROM medical_records WHERE id = %s AND user_id = %s',(record_id, session['user_id']))
    record = cursor.fetchone()  # 获取病历记录
    conn.close()  # 关闭数据库连接
    if record:  # 如果找到记录
        # 返回文件流供用户下载
        return send_file(
            io.BytesIO(record['file_data']),  # 将文件数据转换为字节流
            mimetype=record['file_type'],  # 设置文件类型
            as_attachment=True,  # 强制下载
            download_name=record['file_name']  # 设置下载文件名
        )
    return render_template('error.html', message='文件未找到')  # 如果记录不存在，返回错误页面

# 定义家属页面路由，支持 GET 和 POST 方法
@app.route('/family', methods=['GET', 'POST'])
def family():
    if 'user_id' not in session:  # 如果用户未登录
        return redirect(url_for('login'))  # 重定向到登录页面

    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))
    username = cursor.fetchone()['username']
    if username.startswith('doctor_'):  # 防止签约医师访问
        conn.close()
        return redirect(url_for('login'))

    # 处理 POST 请求（添加或更新家属信息）
    if request.method == 'POST':
        try:
            name = request.form['name']
            relationship = request.form['relationship']
            phone = request.form.get('phone', '')
            address = request.form.get('address', '')
            birth_date = request.form['birth_date'] or None
            health_conditions = request.form['health_conditions']
            if health_conditions == '其他':
                health_conditions = request.form.get('other_health_conditions', '未知')

            # 插入家属信息
            cursor.execute('''
                INSERT INTO family_members (user_id, name, relationship, phone, address, birth_date, health_conditions)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (session['user_id'], name, relationship, phone, address, birth_date, health_conditions))
            conn.commit()
            logging.info(f"用户 {session['user_id']} 添加家属: {name}")
        except pymysql.Error as e:
            conn.rollback()
            logging.error(f"添加家属失败: {e}")
            conn.close()
            return render_template('family.html', error=f"添加家属失败: {str(e)}")

    # 查询当前用户的所有家属信息
    cursor.execute('SELECT * FROM family_members WHERE user_id = %s ORDER BY created_at DESC', (session['user_id'],))
    family_members = cursor.fetchall()
    conn.close()

    # 渲染家属页面
    return render_template('family.html', family_members=family_members, profile_link=url_for('profile'))

# 添加在其他路由定义之后
@app.route('/first_aid_knowledge')
def first_aid_knowledge():
    if 'user_id' not in session:  # 检查用户是否登录
        return redirect(url_for('login'))

    # 检查是否为普通用户（非签约医师）
    conn = get_dbtest_connection()
    if not conn:
        return render_template('error.html', message='数据库连接失败')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = %s', (session['user_id'],))
    username = cursor.fetchone()['username']
    conn.close()
    if username.startswith('doctor_'):
        return redirect(url_for('login'))

    return render_template('first_aid_knowledge.html')

# 定义退出登录路由
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # 从会话中移除用户 ID
    session.pop('physician_id', None)  # 从会话中移除医师 ID
    logging.info("用户退出登录")  # 记录退出日志
    return redirect(url_for('login'))  # 重定向到登录页面

#获取最新的健康数据
def get_latest_health_data(user_id):
    conn = get_daily_data_connection()
    if not conn:
        logging.error("无法连接到 daily_data 数据库")
        return {'error': '健康数据库连接失败'}
    cursor = conn.cursor()
    health_data = {}
    metrics = {
        'calorie': ('calorie_calories', 'calorie_timestamp'),
        'sleep': ('sleep_duration', 'sleep_timestamp'),
        'spo2': ('spo2_spo2', 'spo2_timestamp'),
        'stress': ('stress_stress_level', 'stress_timestamp'),
        'heart_rate': ('heart_rate_heart_rate', 'heart_rate_timestamp'),
        'xiaomifit_device': {
            'avg_hr': ['timestamp'],
            'avg_spo2': ['timestamp'],
            'avg_stress': ['timestamp'],
            'max_hr': ['maxHrTime', 'timestamp'],
            'min_hr': ['minHrTime', 'timestamp'],
            'max_spo2': ['maxSpo2Time', 'timestamp'],
            'min_spo2': ['minSpo2Time', 'timestamp'],
            'max_stress': ['timestamp'],
            'min_stress': ['timestamp'],
            'step': ['timestamp'],
            'total_cal': ['timestamp']
        }
    }

    try:
        cursor.execute('SHOW TABLES')
        tables = cursor.fetchall()
        logging.info(f"daily_data 数据库中的表: {[t['Tables_in_daily_data'] for t in tables]}")
        if not tables:
            health_data['error'] = '暂无健康数据表'
            return health_data

        # 处理带日期前缀的表
        dates = set()
        for table in tables:
            table_name = table['Tables_in_daily_data']
            for metric in metrics.keys():
                match = re.match(rf'(\d{{4}}_\d{{2}}_\d{{2}})_{metric}$', table_name)
                if match:
                    dates.add(match.group(1))
                    break

        if dates:
            latest_date = max(dates)
            health_data['record_date'] = latest_date.replace('_', '-')
            for metric, fields in metrics.items():
                table_name = f"{latest_date}_{metric}"
                if metric == 'xiaomifit_device':
                    try:
                        cursor.execute(f"DESCRIBE {table_name}")
                        columns = [row['Field'] for row in cursor.fetchall()]
                        for x_metric, timestamps in fields.items():
                            field_name = x_metric.replace('_', '').upper()
                            timestamp_field = next((ts for ts in timestamps if ts in columns), None)
                            if field_name not in columns:
                                field_name = next((f for f in columns if x_metric.replace('_', '').lower() in f.lower()), None)
                                if not field_name:
                                    health_data[x_metric] = None
                                    continue
                            if timestamp_field:
                                cursor.execute(f'''
                                    SELECT {field_name} AS value FROM {table_name}
                                    WHERE {timestamp_field} IS NOT NULL ORDER BY {timestamp_field} DESC LIMIT 1
                                ''')
                                result = cursor.fetchone()
                                health_data[x_metric] = result['value'] if result else None
                            else:
                                health_data[x_metric] = None
                    except pymysql.Error as e:
                        logging.error(f"查询 {table_name} 失败: {e}")
                elif metric == 'sleep':
                    try:
                        table_name_sleep = f"{latest_date}_sleep"
                        cursor.execute(f"DESCRIBE {table_name_sleep}")
                        sleep_columns = [row['Field'] for row in cursor.fetchall()]
                        sleep_fields = {
                            'sleep_duration': 'sleep_duration',
                            'sleep_sleep_awake_duration': 'sleep_sleep_awake_duration',
                            'sleep_sleep_deep_duration': 'sleep_sleep_deep_duration',
                            'sleep_sleep_light_duration': 'sleep_sleep_light_duration',
                            'sleep_sleep_rem_duration': 'sleep_sleep_rem_duration',
                            'sleep_sleep_score': 'sleep_sleep_score'
                        }
                        for sleep_metric, field_name in sleep_fields.items():
                            if field_name in sleep_columns:
                                cursor.execute(f'''
                                    SELECT {field_name} AS value FROM {table_name_sleep}
                                    ORDER BY sleep_timestamp DESC LIMIT 1
                                ''')
                                result = cursor.fetchone()
                                if result and result['value']:
                                    try:
                                        health_data[sleep_metric] = int(result['value']) if result['value'].isdigit() else result['value']
                                    except ValueError:
                                        health_data[sleep_metric] = result['value']
                                else:
                                    health_data[sleep_metric] = None
                            else:
                                health_data[sleep_metric] = None
                    except pymysql.Error as e:
                        logging.error(f"查询 {table_name_sleep} 失败: {e}")
                else:
                    value_field, timestamp_field = fields
                    try:
                        cursor.execute(f'''
                            SELECT CAST({value_field} AS SIGNED) AS value FROM {table_name}
                            ORDER BY {timestamp_field} DESC LIMIT 1
                        ''')
                        result = cursor.fetchone()
                        health_data[metric] = result['value'] if result else None
                    except pymysql.Error as e:
                        logging.error(f"查询 {table_name} 失败: {e}")

        # 查询 temperature_data 表
        try:
            cursor.execute("DESCRIBE temperature_data")
            columns = [row['Field'] for row in cursor.fetchall()]
            logging.info(f"temperature_data 表的字段: {columns}")
            temp_fields = ['body_temperature', 'room_temperature', 'humidity']
            for field in temp_fields:
                if field in columns:
                    cursor.execute(f'''
                        SELECT {field} AS value FROM temperature_data
                        ORDER BY timestamp DESC LIMIT 1
                    ''')
                    result = cursor.fetchone()
                    health_data[field] = result['value'] if result else None
                    logging.info(f"从 temperature_data 获取 {field}: {health_data[field]}")
                else:
                    health_data[field] = None
                    logging.warning(f"字段 {field} 在 temperature_data 表中不存在")
        except pymysql.Error as e:
            logging.error(f"查询 temperature_data 失败: {e}")
            health_data['error'] = f"查询温度数据失败: {str(e)}"

    except Exception as e:
        logging.error(f"获取健康数据失败: {e}")
        health_data['error'] = '获取健康数据失败，请稍后重试'
    finally:
        conn.close()
    return health_data

# 检查健康数据是否超出阈值
def check_health_thresholds(health_data):
    # 定义健康指标的正常范围
    thresholds = {
        'heart_rate': (60, 100),  # 心率：60-100 次/分钟
        'spo2': (95, 100),  # 血氧：95-100%
        'stress': (0, 50)  # 压力：0-50
    }
    for metric, (min_val, max_val) in thresholds.items():  # 遍历阈值
        value = health_data.get(metric)  # 获取指标值
        if value and (value < min_val or value > max_val):  # 如果值超出范围
            health_data['alert_message'] = f"{metric} 当前值 {value} 超出范围 ({min_val}-{max_val})"  # 设置警告信息
            return True  # 返回 True 表示异常
    return False  # 返回 False 表示正常

# 预测疾病风险（基于规则）
def predict_disease_risk(profile, health_data, medical_records, emergency_events):
    """简单的 AI 疾病预测函数（基于规则）"""
    prediction = {'risks': [], 'probabilities': {'心脏病': '无法计算'}, 'suggestions': []}  # 初始化预测结果

    if profile:  # 如果有个人信息
        age = profile.get('age', 0)  # 获取年龄
        if age > 65:  # 如果年龄大于 65
            prediction['risks'].append('年龄相关疾病风险（如心脏病、关节炎）')  # 添加风险
            prediction['suggestions'].append('建议定期体检')  # 添加建议
            prediction['probabilities']['心脏病'] = '中等风险'  # 设置心脏病风险

    if 'heart_rate' in health_data and health_data['heart_rate']:  # 如果有心率数据
        hr = health_data['heart_rate']  # 获取心率值
        if hr > 100:  # 如果心率过高
            prediction['risks'].append('心动过速可能提示心脏问题')  # 添加风险
            prediction['suggestions'].append('建议咨询心脏科医生')  # 添加建议
            prediction['probabilities']['心脏病'] = '高风险'  # 设置心脏病高风险
        elif hr < 60:  # 如果心率过低
            prediction['risks'].append('心动过缓可能提示心脏问题')  # 添加风险
            prediction['probabilities']['心脏病'] = '中等风险'  # 设置心脏病中等风险

    if 'spo2' in health_data and health_data['spo2']:  # 如果有血氧数据
        spo2 = health_data['spo2']  # 获取血氧值
        if spo2 < 95:  # 如果血氧过低
            prediction['risks'].append('低血氧可能提示呼吸系统疾病')  # 添加风险
            prediction['suggestions'].append('建议进行肺功能检查')  # 添加建议

    if emergency_events:  # 如果有紧急事件记录
        for event in emergency_events:  # 遍历紧急事件
            if '心脏' in event['event_description']:  # 如果事件描述包含“心脏”
                prediction['risks'].append('历史心脏问题增加复发风险')  # 添加风险
                prediction['suggestions'].append('建议监测心脏健康')  # 添加建议
                prediction['probabilities']['心脏病'] = '高风险'  # 设置心脏病高风险

    if medical_records:  # 如果有病历记录
        for record in medical_records:  # 遍历病历
            if '心电图' in record['file_name']:  # 如果文件名包含“心电图”
                prediction['suggestions'].append('建议复查心电图')  # 添加建议

    if not prediction['risks']:  # 如果没有检测到风险
        prediction['risks'].append('当前无明显疾病风险')  # 添加默认信息
    if not prediction['suggestions']:  # 如果没有建议
        prediction['suggestions'].append('保持健康生活方式')  # 添加默认建议

    return prediction  # 返回预测结果

# 生成健康咨询自动回复（基于规则）
def generate_consultation_response(question, profile, health_data, medical_records, emergency_events):
    """生成健康咨询回复（基于规则）"""
    response = "感谢您的咨询，以下是初步建议：\n"  # 初始化回复内容

    if '疲倦' in question or '累' in question:  # 如果问题提到疲倦
        response += "- 您提到感到疲倦，可能是睡眠不足或压力过大导致。\n"
        if 'sleep_duration' in health_data and health_data['sleep_duration'] and health_data['sleep_duration'] < 6:  # 如果睡眠不足
            response += f"  您的睡眠总时长 ({health_data['sleep_duration']}小时) 偏低，建议每晚保持7-8小时睡眠。\n"
        if 'stress' in health_data and health_data['stress'] and health_data['stress'] > 50:  # 如果压力过高
            response += f"  您的压力值 ({health_data['stress']}) 偏高，建议尝试放松技巧如深呼吸或冥想。\n"
        response += "  如症状持续，建议咨询内科医生。\n"

    elif '心' in question or '胸' in question:  # 如果问题提到心脏或胸部
        response += "- 您提到心脏或胸部相关问题，请关注以下情况：\n"
        if 'heart_rate' in health_data and health_data['heart_rate']:  # 如果有心率数据
            hr = health_data['heart_rate']  # 获取心率值
            if hr > 100:  # 如果心率过高
                response += f"  您的心率 ({hr}) 偏高，可能需要立即咨询心脏科医生。\n"
            elif hr < 60:  # 如果心率过低
                response += f"  您的心率 ({hr}) 偏低，建议观察并咨询医生。\n"
        response += "  如有胸痛或呼吸困难，请拨打120紧急求助。\n"

    else:  # 如果问题不匹配特定关键词
        response += "- 您的提问已收到，以下是基于您健康数据的建议：\n"
        if profile and profile.get('age', 0) > 65:  # 如果年龄大于 65
            response += "  年龄较大，建议定期体检。\n"
        if 'spo2' in health_data and health_data['spo2'] and health_data['spo2'] < 95:  # 如果血氧过低
            response += f"  您的血氧 ({health_data['spo2']}%) 偏低，建议检查呼吸系统。\n"

    response += "- 如需进一步帮助，请提供更多细节或联系专业医生。"  # 添加结束语
    return response  # 返回生成的回复

# 根据用户 ID 获取用户名
def get_username_by_user_id(user_id):
    conn = get_dbtest_connection()  # 获取数据库连接
    if not conn:  # 如果连接失败，返回 None
        return None
    cursor = conn.cursor()  # 创建数据库游标
    cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))  # 查询用户名
    username = cursor.fetchone()  # 获取查询结果
    conn.close()  # 关闭数据库连接
    return username['username'] if username else None  # 返回用户名或 None

# 根据医师 ID 获取用户名
def get_username_by_physician_id(physician_id):
    conn = get_dbtest_connection()  # 获取数据库连接
    if not conn:  # 如果连接失败，返回 None
        return None
    cursor = conn.cursor()  # 创建数据库游标
    cursor.execute('SELECT username FROM physicians WHERE id = %s', (physician_id,))  # 查询用户名
    username = cursor.fetchone()  # 获取查询结果
    conn.close()  # 关闭数据库连接
    return username['username'] if username else None  # 返回用户名或 None

# 主程序入口
if __name__ == '__main__':
    app.run(debug=True)  # 运行 Flask 应用，开启调试模式