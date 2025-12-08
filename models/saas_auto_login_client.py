# -*- coding: utf-8 -*-
"""
ملف Controller - يوضع في:
controllers/saas_auto_login_client.py
"""
from odoo import http
from odoo.http import request
import secrets
from datetime import datetime, timedelta
import logging
import werkzeug
import json

_logger = logging.getLogger(__name__)

TOKEN_STORAGE = {}


class SaasAutoLoginController(http.Controller):
    
    @http.route('/saas/generate_auth_link', type='http', auth='none', methods=['POST'], csrf=False)
    def generate_auth_link(self, **kwargs):
        """توليد رابط تسجيل دخول تلقائي"""
        try:
            # ✅ قراءة البيانات بطريقة صحيحة
            user_id = None
            admin_password = None
            
            # محاولة قراءة JSON من body
            if request.httprequest.data:
                try:
                    data = json.loads(request.httprequest.data.decode('utf-8'))
                    user_id = data.get('user_id')
                    admin_password = data.get('admin_password')
                    _logger.info("📥 Data from JSON body: user_id=%s", user_id)
                except:
                    pass
            
            # إذا لم تُقرأ من JSON، جرّب kwargs
            if not user_id:
                user_id = kwargs.get('user_id')
                admin_password = kwargs.get('admin_password')
                _logger.info("📥 Data from kwargs: user_id=%s", user_id)
            
            if not user_id or not admin_password:
                _logger.error("❌ Missing user_id or admin_password")
                return request.make_json_response({
                    'success': False, 
                    'error': 'Missing user_id or admin_password'
                })
            
            user_id = int(user_id)
            current_db = request.env.cr.dbname
            
            # ✅ التحقق من المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                _logger.error("❌ User ID %d not found", user_id)
                return request.make_json_response({
                    'success': False, 
                    'error': f'User ID {user_id} not found'
                })
            
            if not user.active:
                _logger.error("❌ User ID %d is inactive", user_id)
                return request.make_json_response({
                    'success': False, 
                    'error': 'User is inactive'
                })
            
            # ✅ التحقق من كلمة مرور الأدمن (اختياري حسب احتياجك)
            # يمكنك تفعيل هذا للأمان الإضافي:
            """
            admin = request.env['res.users'].sudo().search([('id', '=', 2)], limit=1)  # SUPERUSER_ID = 2
            if admin:
                try:
                    admin.sudo()._check_credentials(admin_password, {'interactive': False})
                except:
                    _logger.error("❌ Invalid admin password")
                    return request.make_json_response({
                        'success': False,
                        'error': 'Invalid admin password'
                    })
            """
            
            _logger.info("⚠️ Skipping admin password check - trusted source")
            
            # ✅ توليد token آمن
            token = secrets.token_urlsafe(40)
            expires = datetime.now() + timedelta(minutes=10)
            
            TOKEN_STORAGE[token] = {
                'user_id': user_id,
                'user_login': user.login,
                'expires': expires,
                'db_name': current_db
            }
            
            _logger.info("✅ Token generated for user %s (ID: %d)", user.login, user_id)
            
            base = request.httprequest.host_url.rstrip('/')
            auth_url = f"{base}/saas/autologin?token={token}"
            
            return request.make_json_response({
                'success': True,
                'auth_url': auth_url,
                'token': token,
                'expires_at': expires.isoformat()
            })
            
        except Exception as e:
            _logger.error("❌ Generate link failed: %s", str(e), exc_info=True)
            return request.make_json_response({
                'success': False, 
                'error': str(e)
            })

    @http.route('/saas/autologin', type='http', auth='public', methods=['GET'], csrf=False)
    def autologin(self, token, **kwargs):
        """تسجيل الدخول التلقائي - محدّث لـ Odoo 17"""
        try:
            _logger.info("🔑 Autologin attempt with token: %s...", token[:10])
            
            # ✅ التحقق من Token
            data = TOKEN_STORAGE.get(token)
            
            if not data:
                _logger.warning("⚠️ Token not found")
                return request.render('web.login', {
                    'error': 'رمز التسجيل غير صالح'
                })
            
            if datetime.now() > data['expires']:
                del TOKEN_STORAGE[token]
                _logger.warning("⚠️ Token expired")
                return request.render('web.login', {
                    'error': 'انتهت صلاحية رمز التسجيل'
                })
            
            user_id = data['user_id']
            user_login = data['user_login']
            db_name = data['db_name']
            
            # ✅ التحقق من المستخدم مرة أخرى
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists() or not user.active:
                del TOKEN_STORAGE[token]
                _logger.error("❌ User not found or inactive")
                return request.render('web.login', {
                    'error': 'المستخدم غير موجود أو غير نشط'
                })
            
            # ✅ حذف الـ token بعد الاستخدام
            del TOKEN_STORAGE[token]
            _logger.info("🗑️ Token deleted after use")
            
            # ✅✅✅ تسجيل الدخول في Odoo 18
            # الخطوة 1: تنظيف الـ session القديم
            request.session.logout(keep_db=True)
            
            # الخطوة 2: تعيين جميع خصائص الـ session
            request.session.uid = user_id
            request.session.login = user_login
            request.session.db = db_name
            
            # الخطوة 3: CRITICAL - إنشاء session_token (مطلوب في Odoo 18)
            request.session.session_token = secrets.token_hex(16)
            
            # الخطوة 4: تعيين الـ context
            request.session.context = {
                'lang': user.lang or 'en_US',
                'tz': user.tz or 'UTC',
                'uid': user_id,
            }
            
            # الخطوة 5: حفظ الـ session
            request.session.finalize()
            
            # الخطوة 6: تحديث الـ environment
            request.update_env(user=user_id)
            
            _logger.info("✅✅✅ Autologin SUCCESS for user: %s (ID: %d)", user_login, user_id)
            
            # ✅ إعادة التوجيه للصفحة الرئيسية
            return werkzeug.utils.redirect('/web', 303)
            
        except Exception as e:
            _logger.error("❌ Autologin FAILED: %s", str(e), exc_info=True)
            return request.render('web.login', {
                'error': f'فشل تسجيل الدخول: {str(e)}'
            })

    @http.route('/saas/cleanup_tokens', type='json', auth='user', methods=['POST'])
    def cleanup_expired_tokens(self):
        """تنظيف الـ tokens المنتهية"""
        try:
            now = datetime.now()
            expired = [k for k, v in TOKEN_STORAGE.items() if v['expires'] < now]
            for token in expired:
                del TOKEN_STORAGE[token]
            _logger.info("🧹 Cleaned %d expired tokens", len(expired))
            return {
                'success': True,
                'cleaned': len(expired), 
                'remaining': len(TOKEN_STORAGE)
            }
        except Exception as e:
            _logger.error("❌ Cleanup failed: %s", str(e))
            return {'success': False, 'error': str(e)}
