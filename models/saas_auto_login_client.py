# -*- coding: utf-8 -*-
# saas_auto_login_client/controllers/main.py

from odoo import http
from odoo.http import request
import logging
import time

_logger = logging.getLogger(__name__)


class SaasAutoLoginClientController(http.Controller):

    @http.route('/saas/client_login/<string:token>', type='http', auth='public', csrf=False, website=False)
    def client_auto_login(self, token, **kwargs):
        """
        تسجيل دخول تلقائي باستخدام token مؤقت
        """
        try:
            _logger.info("🔐 Received auto-login request with token: %s...", token[:10])

            # البحث عن الـ token في ir.config_parameter
            ICPSudo = request.env['ir.config_parameter'].sudo()
            token_key = f'saas_auto_login_token_{token}'
            token_data = ICPSudo.get_param(token_key)

            if not token_data:
                _logger.error("❌ Token not found or expired: %s", token_key)
                return self._error_response('Invalid or expired token')

            # فك تشفير الـ token: user_id|expiry_timestamp
            try:
                user_id, expiry = token_data.split('|')
                user_id = int(user_id)
                expiry = int(expiry)

                # تحقق من انتهاء الصلاحية
                current_time = int(time.time())
                if current_time > expiry:
                    _logger.error("❌ Token expired: %s (expired at: %s, now: %s)", token_key, expiry, current_time)
                    # حذف الـ token المنتهي
                    ICPSudo.set_param(token_key, False)
                    return self._error_response('Token expired. Please try again.')

            except ValueError as e:
                _logger.error("❌ Invalid token format: %s", str(e))
                return self._error_response('Invalid token format')

            # البحث عن المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                _logger.error("❌ User not found: ID %s", user_id)
                return self._error_response('User not found')

            if not user.active:
                _logger.error("❌ User inactive: %s", user.login)
                return self._error_response('User is inactive')

            _logger.info("✅ Auto-login successful for user: %s (ID: %s)", user.login, user.id)

            # حذف الـ token بعد الاستخدام (one-time use)
            ICPSudo.set_param(token_key, False)

            # تسجيل الدخول مباشرة
            request.session.uid = user.id
            request.session.login = user.login
            request.session.session_token = request.session.sid
            request.session.context = request.env['res.users'].context_get()

            # إعادة توجيه للصفحة الرئيسية
            return request.redirect('/web')

        except Exception as e:
            _logger.error("❌ Auto-login failed: %s", str(e))
            return self._error_response(f'Login failed: {str(e)}')

    def _error_response(self, message):
        """صفحة خطأ"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Auto Login Error</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background: #f5f5f5;
                }}
                .error {{
                    background: #f8d7da;
                    color: #721c24;
                    padding: 30px;
                    border-radius: 8px;
                    display: inline-block;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    max-width: 500px;
                }}
                h2 {{ margin-top: 0; }}
                .retry {{
                    margin-top: 20px;
                    padding: 10px 20px;
                    background: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    display: inline-block;
                }}
                .retry:hover {{
                    background: #0056b3;
                }}
            </style>
        </head>
        <body>
            <div class="error">
                <h2>❌ Auto Login Failed</h2>
                <p>{message}</p>
                <a href="/web/login" class="retry">Go to Login Page</a>
            </div>
        </body>
        </html>
        """
        return request.make_response(html_content, headers=[('Content-Type', 'text/html')])
