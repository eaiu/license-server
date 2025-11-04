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

# 全局 Supabase 客户端
_supabase_client = None


def get_supabase():
    """获取 Supabase 客户端"""
    global _supabase_client

    if _supabase_client is None:
        # 检查环境变量
        if not SUPABASE_URL or not SUPABASE_KEY:
            print(f"[ERROR] 环境变量缺失:")
            print(f"  SUPABASE_URL: {'✓' if SUPABASE_URL else '✗ 缺失'}")
            print(f"  SUPABASE_KEY: {'✓' if SUPABASE_KEY else '✗ 缺失'}")
            print(f"  SECRET_KEY: {'✓' if SECRET_KEY else '✗ 缺失'}")
            return None

        try:
            from supabase import create_client, Client
            print(f"[INFO] 初始化 Supabase: {SUPABASE_URL[:30]}...")
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
            print(f"[INFO] Supabase 客户端创建成功")
            return _supabase_client
        except ImportError as e:
            print(f"[ERROR] Supabase 库导入失败: {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Supabase 初始化失败: {e}")
            import traceback
            traceback.print_exc()
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
        'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
        'Access-Control-Allow-Headers': 'Content-Type',
    }


class handler(BaseHTTPRequestHandler):
    """Vercel Serverless 函数处理器"""

    def do_OPTIONS(self):
        """处理 CORS 预检请求"""
        self.send_response(200)
        for key, value in cors_headers().items():
            self.send_header(key, value)
        self.end_headers()

    def do_GET(self):
        """健康检查端点"""
        supabase = get_supabase()

        return self.send_json_response(200, {
            'status': 'ok',
            'message': 'License verification API is running',
            'environment': {
                'SECRET_KEY': '✓ 已设置' if SECRET_KEY else '✗ 未设置',
                'SUPABASE_URL': '✓ 已设置' if SUPABASE_URL else '✗ 未设置',
                'SUPABASE_KEY': '✓ 已设置' if SUPABASE_KEY else '✗ 未设置',
                'SUPABASE_CLIENT': '✓ 连接成功' if supabase else '✗ 连接失败',
            }
        })

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

            print(f"[INFO] 收到验证请求: {license_key[:20]}..., {machine_id[:20]}...")

            # 3. 基础验证
            if not all([license_key, machine_id, signature]):
                return self.send_json_response(400, {
                    'valid': False,
                    'message': '参数不完整'
                })

            # 4. 验证时间戳
            current_time = int(time.time())
            time_diff = abs(current_time - timestamp)
            print(f"[INFO] 时间差: {time_diff}秒")

            if time_diff > 300:
                return self.send_json_response(400, {
                    'valid': False,
                    'message': f'请求时间无效（时间差{time_diff}秒）'
                })

            # 5. 验证签名
            if not verify_signature(license_key, machine_id, timestamp, signature):
                print(f"[WARN] 签名验证失败")
                return self.send_json_response(403, {
                    'valid': False,
                    'message': '签名验证失败'
                })

            print(f"[INFO] 签名验证通过")

            # 6. 连接数据库
            supabase = get_supabase()
            if not supabase:
                print(f"[ERROR] 无法连接数据库")
                return self.send_json_response(500, {
                    'valid': False,
                    'message': '数据库连接失败，请检查环境变量',
                    'debug': {
                        'SUPABASE_URL': bool(SUPABASE_URL),
                        'SUPABASE_KEY': bool(SUPABASE_KEY)
                    }
                })

            # 7. 查询许可证
            print(f"[INFO] 查询许可证: {license_key}")
            result = supabase.table('licenses').select('*').eq('license_key', license_key).execute()

            if not result.data:
                print(f"[WARN] 许可证不存在: {license_key}")
                return self.send_json_response(404, {
                    'valid': False,
                    'message': '许可证不存在'
                })

            license_info = result.data[0]
            print(f"[INFO] 找到许可证，过期时间: {license_info.get('expire_time')}")

            # 8. 验证状态
            if not license_info.get('is_active', False):
                return self.send_json_response(403, {
                    'valid': False,
                    'message': '许可证已被禁用'
                })

            # 9. 验证过期时间
            expire_time = license_info['expire_time']
            if current_time > expire_time:
                expire_date = datetime.fromtimestamp(expire_time).strftime('%Y-%m-%d')
                return self.send_json_response(403, {
                    'valid': False,
                    'message': f"许可证已于 {expire_date} 过期"
                })

            # 10. 机器码绑定
            bound_machine = license_info.get('machine_id') or ''
            max_devices = license_info.get('max_devices', 1)

            if bound_machine:
                machines = [m.strip() for m in bound_machine.split(',') if m.strip()]
                if machine_id not in machines:
                    if len(machines) >= max_devices:
                        return self.send_json_response(403, {
                            'valid': False,
                            'message': f'许可证已绑定 {len(machines)} 台设备（上限 {max_devices}）'
                        })
                    # 绑定新设备
                    machines.append(machine_id)
                    print(f"[INFO] 绑定新设备: {machine_id}")
                    supabase.table('licenses').update({
                        'machine_id': ','.join(machines)
                    }).eq('license_key', license_key).execute()
            else:
                # 首次激活
                print(f"[INFO] 首次激活，绑定设备: {machine_id}")
                supabase.table('licenses').update({
                    'machine_id': machine_id,
                    'activated_at': current_time
                }).eq('license_key', license_key).execute()

            # 11. 记录日志
            try:
                supabase.table('verify_logs').insert({
                    'license_key': license_key,
                    'machine_id': machine_id,
                    'verify_time': current_time,
                    'ip_address': self.headers.get('X-Forwarded-For', self.client_address[0])
                }).execute()
            except Exception as log_error:
                print(f"[WARN] 日志记录失败: {log_error}")

            # 12. 返回成功
            days_left = max(0, (expire_time - current_time) // 86400)
            print(f"[INFO] 验证成功，剩余 {days_left} 天")

            return self.send_json_response(200, {
                'valid': True,
                'expire_time': expire_time,
                'days_remaining': days_left,
                'message': '验证成功'
            })

        except json.JSONDecodeError:
            print(f"[ERROR] JSON 解析失败")
            return self.send_json_response(400, {
                'valid': False,
                'message': 'JSON 格式错误'
            })
        except Exception as e:
            print(f"[ERROR] 未知错误: {str(e)}")
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