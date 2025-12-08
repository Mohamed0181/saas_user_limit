# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
import secrets
from datetime import datetime, timedelta
import logging

_logger = logging.getLogger(__name__)

TOKEN_STORAGE = {}


class SaasAutoLoginController(http.Controller):
    
    @http.route('/saas/generate_auth_link', type='json', auth='none', methods=['POST'], csrf=False)
    def generate_auth_link(self, **kwargs):
        """توليد رابط تسجيل دخول تلقائي"""
        try:
            # ✅ استخراج الـ parameters من kwargs
            user_id = kwargs.get('user_id')
            admin_password = kwargs.get('admin_password')
            
            _logger.info("🔍 Request received - user_id: %s", user_id)
            
            if not user_id or not admin_password:
                return {'success': False, 'error': 'Missing user_id or admin_password'}
            
            user_id = int(user_id)
            
            # تحقق من كلمة سر الأدمن
            admin = request.env['res.users'].sudo().search([('login', '=', 'admin')], limit=1)
            if not admin:
                _logger.error("❌ Admin user not found")
                return {'success': False, 'error': 'Admin not found'}
            
            try:
                admin.sudo()._check_credentials(admin_password, {'interactive': False})
                _logger.info("✅ Admin password verified")
            except Exception as e:
                _logger.error("❌ Wrong admin password: %s", str(e))
                return {'success': False, 'error': 'Wrong admin password'}
            
            # التحقق من المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                _logger.error("❌ User not found: %d", user_id)
                return {'success': False, 'error': 'User not found'}
            
            # توليد token آمن
            token = secrets.token_urlsafe(40)
            expires = datetime.now() + timedelta(minutes=10)
            
            # حفظ في الذاكرة المؤقتة
            TOKEN_STORAGE[token] = {
                'user_id': user_id,
                'user_login': user.login,
                'expires': expires,
                'db_name': request.env.cr.dbname
            }
            
            _logger.info("✅ Token generated for user %s (ID: %d)", user.login, user_id)
            
            base = request.httprequest.host_url.rstrip('/')
            auth_url = f"{base}/saas/autologin?token={token}"
            
            return {
                'success': True,
                'auth_url': auth_url,
                'token': token,
                'expires_at': expires.isoformat()
            }
            
        except Exception as e:
            _logger.error("❌ Generate link failed: %s", str(e), exc_info=True)
            return {'success': False, 'error': str(e)}

    @http.route('/saas/autologin', type='http', auth='none', methods=['GET'], csrf=False)
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
            
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists() or not user.active:
                del TOKEN_STORAGE[token]
                _logger.error("❌ User not found or inactive (ID: %d)", user_id)
                return request.render('web.login', {
                    'error': 'المستخدم غير موجود أو غير مفعل'
                })
            
            # حذف الـ token (استخدام لمرة واحدة فقط)
            del TOKEN_STORAGE[token]
            _logger.info("🗑️ Token used and deleted")
            
            # 🎯 تسجيل الدخول الفعلي
            request.session.uid = user_id
            request.session.login = user_login
            request.session.password = secrets.token_urlsafe(16)
            request.session.context = {
                'lang': user.lang or 'en_US',
                'tz': user.tz or 'UTC',
                'uid': user_id,
            }
            
            # تحديث environment
            request.uid = user_id
            
            _logger.info("✅✅✅ Autologin SUCCESS for user: %s (ID: %d)", user_login, user_id)
            
            return request.redirect('/web')
            
        except Exception as e:
            _logger.error("❌ Autologin FAILED: %s", str(e), exc_info=True)
            return request.render('web.login', {
                'error': f'فشل تسجيل الدخول التلقائي: {str(e)}'
            })

    @http.route('/saas/cleanup_tokens', type='json', auth='none', methods=['POST'])
    def cleanup_expired_tokens(self):
        """تنظيف الـ tokens المنتهية"""
        now = datetime.now()
        expired = [k for k, v in TOKEN_STORAGE.items() if v['expires'] < now]
        for token in expired:
            del TOKEN_STORAGE[token]
        _logger.info("🧹 Cleaned %d expired tokens", len(expired))
        return {'cleaned': len(expired), 'remaining': len(TOKEN_STORAGE)}
