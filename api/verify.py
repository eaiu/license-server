from flask import Flask, request, jsonify
import hashlib
import hmac
import time
import os
from datetime import datetime
from supabase import create_client, Client

app = Flask(__name__)

# 环境变量
SECRET_KEY = os.getenv('SECRET_KEY', '').encode()
SUPABASE_URL = os.getenv('SUPABASE_URL', '')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', '')

# 初始化 Supabase 客户端
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL else None


def verify_signature(license_key, machine_id, timestamp, signature):
    """验证请求签名"""
    msg = f"{license_key}{machine_id}{timestamp}"
    expected = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.route('/api/verify', methods=['POST', 'OPTIONS'])
def verify_license():
    # CORS 预检
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.json
        license_key = data.get('license_key', '').strip()
        machine_id = data.get('machine_id', '').strip()
        timestamp = int(data.get('timestamp', 0))
        signature = data.get('signature', '')

        # 1. 参数验证
        if not all([license_key, machine_id, signature]):
            return jsonify({'valid': False, 'message': '参数不完整'}), 400

        # 2. 时间戳验证（防重放攻击）
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:  # 5分钟容差
            return jsonify({'valid': False, 'message': '请求已过期'}), 400

        # 3. 签名验证
        if not verify_signature(license_key, machine_id, timestamp, signature):
            return jsonify({'valid': False, 'message': '签名验证失败'}), 403

        # 4. 查询许可证
        if not supabase:
            return jsonify({'valid': False, 'message': '数据库未配置'}), 500

        response = supabase.table('licenses').select('*').eq('license_key', license_key).execute()

        if not response.data:
            return jsonify({'valid': False, 'message': '许可证不存在'}), 404

        license_info = response.data[0]

        # 5. 验证状态
        if not license_info.get('is_active'):
            return jsonify({'valid': False, 'message': '许可证已禁用'}), 403

        # 6. 验证过期时间
        expire_time = license_info['expire_time']
        if current_time > expire_time:
            return jsonify({
                'valid': False,
                'message': f"已过期 ({datetime.fromtimestamp(expire_time).strftime('%Y-%m-%d')})"
            }), 403

        # 7. 机器码绑定逻辑
        bound_machine = license_info.get('machine_id') or ''
        max_devices = license_info.get('max_devices', 1)

        if bound_machine:
            machines = [m.strip() for m in bound_machine.split(',') if m.strip()]
            if machine_id not in machines:
                if len(machines) >= max_devices:
                    return jsonify({
                        'valid': False,
                        'message': f'已绑定 {len(machines)} 台设备（上限 {max_devices}）'
                    }), 403
                # 新增设备
                machines.append(machine_id)
                supabase.table('licenses').update({
                    'machine_id': ','.join(machines)
                }).eq('license_key', license_key).execute()
        else:
            # 首次激活
            supabase.table('licenses').update({
                'machine_id': machine_id,
                'activated_at': current_time
            }).eq('license_key', license_key).execute()

        # 8. 记录日志
        try:
            supabase.table('verify_logs').insert({
                'license_key': license_key,
                'machine_id': machine_id,
                'verify_time': current_time,
                'ip_address': request.headers.get('X-Forwarded-For', request.remote_addr)
            }).execute()
        except:
            pass  # 日志失败不影响验证

        # 9. 返回成功
        days_left = max(0, (expire_time - current_time) // 86400)
        return jsonify({
            'valid': True,
            'expire_time': expire_time,
            'days_remaining': days_left,
            'message': '验证成功'
        }), 200

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({
            'valid': False,
            'message': f'服务器错误'
        }), 500


@app.after_request
def after_request(response):
    """设置 CORS 头"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    return response


# ===== Vercel 入口（关键！）=====
def handler(request):
    """Vercel Serverless 函数处理器"""
    with app.request_context(request.environ):
        try:
            rv = app.preprocess_request()
            if rv is None:
                rv = app.dispatch_request()
        except Exception as e:
            rv = app.handle_user_exception(e)
        response = app.make_response(rv)
        return app.process_response(response)