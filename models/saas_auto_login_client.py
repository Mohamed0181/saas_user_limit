# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
import secrets
from datetime import datetime, timedelta
import logging

_logger = logging.getLogger(__name__)

# تخزين مؤقت للـ tokens (أفضل من ir.config_parameter)
TOKEN_STORAGE = {}


class SaasAutoLoginController(http.Controller):
    
    @http.route('/saas/generate_auth_link', type='json', auth='none', methods=['POST'], csrf=False)
    def generate_auth_link(self, user_id, admin_password, **kwargs):
        """توليد رابط تسجيل دخول تلقائي"""
        try:
            # تحقق من كلمة سر الأدمن
            admin = request.env['res.users'].sudo().search([('login', '=', 'admin')], limit=1)
            if not admin:
                _logger.error("Admin user not found")
                return {'success': False, 'error': 'Admin not found'}
            
            try:
                admin.sudo()._check_credentials(admin_password, {'interactive': False})
            except Exception as e:
                _logger.error("Wrong admin password: %s", str(e))
                return {'success': False, 'error': 'Wrong admin password'}
            
            # التحقق من المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                return {'success': False, 'error': 'User not found'}
            
            # توليد token آمن
            token = secrets.token_urlsafe(40)
            expires = datetime.now() + timedelta(minutes=10)
            
            # حفظ في الذاكرة المؤقتة
            TOKEN_STORAGE[token] = {
                'user_id': user_id,
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
            
            # جلب بيانات الـ token
            data = TOKEN_STORAGE.get(token)
            
            if not data:
                _logger.warning("⚠️ Token not found or already used")
                return request.render('web.login', {
                    'error': 'رمز التسجيل غير صالح أو تم استخدامه مسبقاً'
                })
            
            # التحقق من صلاحية الـ token
            if datetime.now() > data['expires']:
                del TOKEN_STORAGE[token]
                _logger.warning("⚠️ Token expired")
                return request.render('web.login', {
                    'error': 'انتهت صلاحية رمز التسجيل'
                })
            
            user_id = data['user_id']
            
            # التحقق من المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists() or not user.active:
                del TOKEN_STORAGE[token]
                _logger.error("❌ User not found or inactive (ID: %d)", user_id)
                return request.render('web.login', {
                    'error': 'المستخدم غير موجود أو غير مفعل'
                })
            
            # حذف الـ token (استخدام لمرة واحدة فقط)
            del TOKEN_STORAGE[token]
            
            # 🎯 السطور الذهبية - تسجيل الدخول الفعلي
            request.session.authenticate(
                request.env.cr.dbname,
                user.login,
                user.partner_id.signup_token or secrets.token_urlsafe(16)
            )
            
            # أو الطريقة البديلة (أكثر أماناً):
            request.session.uid = user_id
            request.session.login = user.login
            request.session.session_token = user.partner_id.signup_token or secrets.token_urlsafe(40)
            request.session.context = request.env['ir.http']._authenticate(user.login, request.session.session_token)
            
            _logger.info("✅ Autologin SUCCESS for user: %s (ID: %d)", user.login, user_id)
            
            # إعادة التوجيه للداشبورد
            return request.redirect('/web')
            
        except Exception as e:
            _logger.error("❌ Autologin FAILED: %s", str(e), exc_info=True)
            return request.render('web.login', {
                'error': f'فشل تسجيل الدخول التلقائي: {str(e)}'
            })

    @http.route('/saas/cleanup_tokens', type='json', auth='user', methods=['POST'])
    def cleanup_expired_tokens(self):
        """تنظيف الـ tokens المنتهية (يمكن استدعاؤه من cron)"""
        now = datetime.now()
        expired = [k for k, v in TOKEN_STORAGE.items() if v['expires'] < now]
        for token in expired:
            del TOKEN_STORAGE[token]
        _logger.info("🧹 Cleaned %d expired tokens", len(expired))
        return {'cleaned': len(expired)}
