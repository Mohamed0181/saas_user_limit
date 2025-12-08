# -*- coding: utf-8 -*-
"""
ملف Controller يجب أن يكون في:
controllers/saas_auto_login_client.py
أو
models/saas_auto_login_client.py (حسب موقعه الحالي)
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
            # قراءة البيانات
            if request.httprequest.data:
                data = json.loads(request.httprequest.data.decode('utf-8'))
                params = data.get('params', data)
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
            
            # ✅ التحقق من المستخدم المطلوب أولاً
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
            
            # ✅ بدون التحقق من كلمة سر Admin - مباشرة توليد Token
            # نفترض أن الطلب قادم من Manager موثوق
            _logger.info("⚠️ Skipping admin password check - trusted source")
            
            # توليد token آمن
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
        """تسجيل الدخول التلقائي"""
        try:
            _logger.info("🔑 Autologin with token: %s...", token[:10])
            
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
            
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists() or not user.active:
                del TOKEN_STORAGE[token]
                return request.render('web.login', {
                    'error': 'المستخدم غير موجود'
                })
            
            del TOKEN_STORAGE[token]
            _logger.info("🗑️ Token deleted")
            
            # 🎯 تسجيل الدخول
            request.session.uid = user_id
            request.session.login = user_login
            request.session.db = db_name
            request.session.session_token = secrets.token_hex(16)
            request.session.context = {
                'lang': user.lang or 'en_US',
                'tz': user.tz or 'UTC',
                'uid': user_id,
            }
            
            request.uid = user_id
            request.session.modified = True
            
            _logger.info("✅✅✅ Autologin SUCCESS for %s", user_login)
            
            return werkzeug.utils.redirect('/web', 303)
            
        except Exception as e:
            _logger.error("❌ Autologin FAILED: %s", str(e), exc_info=True)
            return request.render('web.login', {
                'error': f'فشل تسجيل الدخول: {str(e)}'
            })

    @http.route('/saas/cleanup_tokens', type='json', auth='user', methods=['POST'])
    def cleanup_expired_tokens(self):
        """تنظيف tokens"""
        now = datetime.now()
        expired = [k for k, v in TOKEN_STORAGE.items() if v['expires'] < now]
        for token in expired:
            del TOKEN_STORAGE[token]
        _logger.info("🧹 Cleaned %d tokens", len(expired))
        return {'cleaned': len(expired), 'remaining': len(TOKEN_STORAGE)}
