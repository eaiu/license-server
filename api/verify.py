# api/verify.py
from http.server import BaseHTTPRequestHandler
import json
import hashlib
import hmac
import time
import os
from datetime import datetime

# 环境变量
SECRET_KEY = os.getenv('SECRET_KEY', '').encode()
SUPABASE_URL = os.getenv('SUPABASE_URL', '')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', '')

# Supabase 客户端（延迟初始化）
_supabase_client = None


def get_supabase():
    """获取 Supabase 客户端（单例模式）"""
    global _supabase_client
    if _supabase_client is None:
        try:
            from supabase import create_client
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            print(f"Supabase init error: {e}")
            return None
    return _supabase_client


def verify_signature(license_key, machine_id, timestamp, signature):
    """验证签名"""
    msg = f"{license_key}{machine_id}{timestamp}"
    expected = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def cors_headers():
    """CORS 响应头"""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    }


class handler(BaseHTTPRequestHandler):
    """Vercel Serverless 函数处理器"""

    def do_OPTIONS(self):
        """处理预检请求"""
        self.send_response(200)
        for key, value in cors_headers().items():
            self.send_header(key, value)
        self.end_headers()

    def do_POST(self):
        """处理 POST 请求"""
        try:
            # 1. 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            # 2. 提取参数
            license_key = data.get('license_key', '').strip()
            machine_id = data.get('machine_id', '').strip()
            timestamp = int(data.get('timestamp', 0))
            signature = data.get('signature', '')

            print(f"[INFO] Request: {license_key}, {machine_id}, {timestamp}")

            # 3. 基础验证
            if not all([license_key, machine_id, signature]):
                return self.send_json_response(400, {
                    'valid': False,
                    'message': '参数不完整'
                })

            # 4. 验证时间戳
            current_time = int(time.time())
            if abs(current_time - timestamp) > 300:
                return self.send_json_response(400, {
                    'valid': False,
                    'message': '请求时间无效'
                })

            # 5. 验证签名
            if not verify_signature(license_key, machine_id, timestamp, signature):
                return self.send_json_response(403, {
                    'valid': False,
                    'message': '签名验证失败'
                })

            # 6. 查询数据库
            supabase = get_supabase()
            if not supabase:
                return self.send_json_response(500, {
                    'valid': False,
                    'message': '数据库连接失败'
                })

            result = supabase.table('licenses').select('*').eq('license_key', license_key).execute()

            if not result.data:
                return self.send_json_response(404, {
                    'valid': False,
                    'message': '许可证不存在'
                })

            license_info = result.data[0]

            # 7. 验证许可证状态
            if not license_info.get('is_active', False):
                return self.send_json_response(403, {
                    'valid': False,
                    'message': '许可证已禁用'
                })

            # 8. 验证过期时间
            expire_time = license_info['expire_time']
            if current_time > expire_time:
                return self.send_json_response(403, {
                    'valid': False,
                    'message': f"许可证已过期"
                })

            # 9. 机器码绑定逻辑
            bound_machine = license_info.get('machine_id') or ''
            max_devices = license_info.get('max_devices', 1)

            if bound_machine:
                machines = [m.strip() for m in bound_machine.split(',') if m.strip()]
                if machine_id not in machines:
                    if len(machines) >= max_devices:
                        return self.send_json_response(403, {
                            'valid': False,
                            'message': f'已绑定{len(machines)}台设备（上限{max_devices}）'
                        })
                    # 添加新设备
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

            # 10. 记录日志
            try:
                supabase.table('verify_logs').insert({
                    'license_key': license_key,
                    'machine_id': machine_id,
                    'verify_time': current_time,
                    'ip_address': self.headers.get('X-Forwarded-For', self.client_address[0])
                }).execute()
            except:
                pass

            # 11. 返回成功
            days_left = max(0, (expire_time - current_time) // 86400)
            return self.send_json_response(200, {
                'valid': True,
                'expire_time': expire_time,
                'days_remaining': days_left,
                'message': '验证成功'
            })

        except json.JSONDecodeError:
            return self.send_json_response(400, {
                'valid': False,
                'message': 'JSON 格式错误'
            })
        except Exception as e:
            print(f"[ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
            return self.send_json_response(500, {
                'valid': False,
                'message': f'服务器错误: {str(e)}'
            })

    def send_json_response(self, status_code, data):
        """发送 JSON 响应"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        for key, value in cors_headers().items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))