# -*- coding: utf-8 -*-
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
            # قراءة البيانات
            if request.httprequest.data:
                data = json.loads(request.httprequest.data.decode('utf-8'))
                if 'params' in data:
                    params = data['params']
                else:
                    params = data
                    
                user_id = params.get('user_id')
                admin_password = params.get('admin_password')
            else:
                user_id = kwargs.get('user_id')
                admin_password = kwargs.get('admin_password')
            
            _logger.info("🔍 Request received - user_id: %s", user_id)
            
            if not user_id or not admin_password:
                return request.make_json_response({
                    'success': False, 
                    'error': 'Missing user_id or admin_password'
                })
            
            user_id = int(user_id)
            current_db = request.env.cr.dbname
            
            # ✅ التحقق من المستخدم المطلوب
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                _logger.error("❌ User ID %d not found in db: %s", user_id, current_db)
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
            
            # ✅ البحث عن مستخدم الأدمن
            admin = request.env['res.users'].sudo().search([
                '|', ('login', '=', 'admin'), ('id', '=', 2)
            ], limit=1)
            
            if not admin:
                _logger.error("❌ Admin user not found in db: %s", current_db)
                return request.make_json_response({
                    'success': False, 
                    'error': 'Admin user not found in database'
                })
            
            # ✅ التحقق من كلمة سر الأدمن
            try:
                admin._check_credentials(admin_password, {'interactive': False})
                _logger.info("✅ Admin password verified in db: %s", current_db)
            except Exception as e:
                _logger.error("❌ Wrong admin password in db %s: %s", current_db, str(e))
                return request.make_json_response({
                    'success': False, 
                    'error': 'Wrong admin password'
                })
            
            # ✅ توليد token آمن
            token = secrets.token_urlsafe(40)
            expires = datetime.now() + timedelta(minutes=10)
            
            # حفظ في الذاكرة المؤقتة
            TOKEN_STORAGE[token] = {
                'user_id': user_id,
                'user_login': user.login,
                'expires': expires,
                'db_name': current_db
            }
            
            _logger.info("✅ Token generated for user %s (ID: %d) in db: %s", 
                        user.login, user_id, current_db)
            
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
        """تسجيل الدخول التلقائي باستخدام الـ token"""
        try:
            _logger.info("🔑 Autologin attempt with token: %s...", token[:10])
            
            data = TOKEN_STORAGE.get(token)
            
            if not data:
                _logger.warning("⚠️ Token not found or already used")
                return request.render('web.login', {
                    'error': 'رمز التسجيل غير صالح أو تم استخدامه مسبقاً'
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
            
            _logger.info("🔐 Attempting login for user: %s (ID: %d) in db: %s", 
                        user_login, user_id, db_name)
            
            # التحقق من المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists() or not user.active:
                del TOKEN_STORAGE[token]
                _logger.error("❌ User not found or inactive (ID: %d)", user_id)
                return request.render('web.login', {
                    'error': 'المستخدم غير موجود أو غير مفعل'
                })
            
            # حذف الـ token
            del TOKEN_STORAGE[token]
            _logger.info("🗑️ Token used and deleted")
            
            # 🎯 تسجيل الدخول بطريقة Odoo الرسمية
            request.session.authenticate(db_name, user_login, user_login)
            
            # تحديث معلومات الـ session
            request.session.uid = user_id
            request.session.login = user_login
            request.session.session_token = request.session.sid
            
            # تحديث الـ context
            request.session.context = dict(request.session.context or {})
            request.session.context.update({
                'lang': user.lang or 'en_US',
                'tz': user.tz or 'UTC',
                'uid': user_id,
            })
            
            _logger.info("✅✅✅ Autologin SUCCESS for user: %s (ID: %d) in db: %s", 
                        user_login, user_id, db_name)
            
            # إعادة التوجيه للصفحة الرئيسية
            return werkzeug.utils.redirect('/web', 303)
            
        except Exception as e:
            _logger.error("❌ Autologin FAILED: %s", str(e), exc_info=True)
            return request.render('web.login', {
                'error': f'فشل تسجيل الدخول التلقائي: {str(e)}'
            })

    @http.route('/saas/cleanup_tokens', type='json', auth='user', methods=['POST'])
    def cleanup_expired_tokens(self):
        """تنظيف الـ tokens المنتهية"""
        now = datetime.now()
        expired = [k for k, v in TOKEN_STORAGE.items() if v['expires'] < now]
        for token in expired:
            del TOKEN_STORAGE[token]
        _logger.info("🧹 Cleaned %d expired tokens", len(expired))
        return {'cleaned': len(expired), 'remaining': len(TOKEN_STORAGE)}
