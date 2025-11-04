from flask import Flask, request, jsonify
import hashlib
import hmac
import time
import os
import json
from datetime import datetime

# Vercel的Serverless函数处理器
app = Flask(__name__)

# 从环境变量获取密钥
SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key').encode()
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

# 简单的内存数据库（仅用于测试，生产环境用Supabase）
LICENSE_CACHE = {}


def get_supabase_client():
    """获取Supabase客户端"""
    try:
        from supabase import create_client
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except:
        return None


def verify_signature(license_key, machine_id, timestamp, signature):
    """验证请求签名"""
    msg = f"{license_key}{machine_id}{timestamp}"
    expected = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.route('/api/verify', methods=['POST', 'OPTIONS'])
def verify_license():
    # 处理CORS预检请求
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    try:
        data = request.json

        license_key = data.get('license_key', '').strip()
        machine_id = data.get('machine_id', '').strip()
        timestamp = data.get('timestamp', 0)
        signature = data.get('signature', '')

        # 基础验证
        if not all([license_key, machine_id, signature]):
            return jsonify({
                'valid': False,
                'message': '参数不完整'
            }), 400

        # 验证时间戳（防止重放攻击，允许5分钟误差）
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:
            return jsonify({
                'valid': False,
                'message': '请求时间无效，请检查系统时间'
            }), 400

        # 验证签名
        if not verify_signature(license_key, machine_id, timestamp, signature):
            return jsonify({
                'valid': False,
                'message': '签名验证失败'
            }), 403

        # 查询许可证（优先使用Supabase）
        supabase = get_supabase_client()

        if supabase:
            # 使用Supabase数据库
            result = supabase.table('licenses').select('*').eq('license_key', license_key).execute()

            if not result.data:
                return jsonify({
                    'valid': False,
                    'message': '许可证不存在或已失效'
                }), 404

            license_info = result.data[0]
        else:
            # 降级到内存数据库（仅测试用）
            license_info = LICENSE_CACHE.get(license_key)
            if not license_info:
                return jsonify({
                    'valid': False,
                    'message': '许可证不存在（数据库未连接）'
                }), 404

        # 验证许可证状态
        if not license_info.get('is_active', False):
            return jsonify({
                'valid': False,
                'message': '许可证已被禁用'
            }), 403

        # 验证过期时间
        expire_time = license_info.get('expire_time', 0)
        if current_time > expire_time:
            return jsonify({
                'valid': False,
                'message': f"许可证已于 {datetime.fromtimestamp(expire_time).strftime('%Y-%m-%d')} 过期"
            }), 403

        # 验证或绑定机器码
        bound_machine = license_info.get('machine_id')
        max_devices = license_info.get('max_devices', 1)

        if bound_machine:
            # 已绑定机器码，验证是否匹配
            bound_list = bound_machine.split(',') if ',' in bound_machine else [bound_machine]

            if machine_id not in bound_list:
                if len(bound_list) >= max_devices:
                    return jsonify({
                        'valid': False,
                        'message': f'许可证已绑定其他设备（最多{max_devices}台）'
                    }), 403
                else:
                    # 添加新设备
                    bound_list.append(machine_id)
                    new_machines = ','.join(bound_list)

                    if supabase:
                        supabase.table('licenses').update({
                            'machine_id': new_machines
                        }).eq('license_key', license_key).execute()
        else:
            # 首次激活，绑定机器码
            if supabase:
                supabase.table('licenses').update({
                    'machine_id': machine_id,
                    'activated_at': current_time
                }).eq('license_key', license_key).execute()

        # 记录验证日志
        if supabase:
            supabase.table('verify_logs').insert({
                'license_key': license_key,
                'machine_id': machine_id,
                'verify_time': current_time,
                'ip_address': request.headers.get('X-Forwarded-For', request.remote_addr)
            }).execute()

        # 返回成功
        return jsonify({
            'valid': True,
            'expire_time': expire_time,
            'days_remaining': max(0, (expire_time - current_time) // 86400),
            'message': '验证成功'
        }), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({
            'valid': False,
            'message': f'服务器错误: {str(e)}'
        }), 500


# CORS配置
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    return response


# Vercel入口（必须）
def handler(request):
    with app.request_context(request.environ):
        return app.full_dispatch_request()