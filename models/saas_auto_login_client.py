# -*- coding: utf-8 -*-
# saas_auto_login_client/controllers/main.py

from odoo import http
from odoo.http import request
import logging
import time
import werkzeug

_logger = logging.getLogger(__name__)


class SaasAutoLoginClientController(http.Controller):

    @http.route('/saas/client_login/<string:token>', type='http', auth='public', csrf=False, website=False)
    def client_auto_login(self, token, **kwargs):
        """
        تسجيل دخول تلقائي باستخدام token مؤقت
        """
        try:
            _logger.info("🔐 Received auto-login request with token: %s...", token[:10])
            
            # البحث عن الـ token
            token_key = f'saas_auto_login_token_{token}'
            token_data = request.env['ir.config_parameter'].sudo().get_param(token_key)

            if not token_data:
                _logger.error("❌ Token not found: %s", token_key)
                return self._error_response('Invalid or expired token')

            # فك تشفير الـ token
            try:
                user_id, expiry = token_data.split('|')
                user_id = int(user_id)
                expiry = int(expiry)

                # تحقق من انتهاء الصلاحية
                if int(time.time()) > expiry:
                    _logger.error("❌ Token expired")
                    request.env['ir.config_parameter'].sudo().set_param(token_key, False)
                    return self._error_response('Token expired. Please try again.')

            except ValueError:
                return self._error_response('Invalid token format')

            # البحث عن المستخدم
            user = request.env['res.users'].sudo().browse(user_id)
            
            if not user.exists() or not user.active:
                _logger.error("❌ User not found or inactive: ID %s", user_id)
                return self._error_response('User not found or inactive')

            _logger.info("✅ User validated: %s (ID: %s)", user.login, user.id)

            # حذف الـ token
            request.env['ir.config_parameter'].sudo().set_param(token_key, False)

            # ✨ الحل النهائي: تحديث session مباشرة
            request.session.uid = user_id
            request.session.login = user.login
            request.session.db = request.db
            request.session.session_token = request.session.sid
            
            # تحديث context
            request.session.context = {
                'lang': user.lang,
                'tz': user.tz,
                'uid': user_id,
            }
            
            _logger.info("✅ Session updated - UID: %s, Login: %s", user_id, user.login)
            
            # Redirect مع معلومات الـ session
            response = werkzeug.utils.redirect('/web')
            
            # إضافة session_id للـ cookie
            response.set_cookie('session_id', request.session.sid)
            
            return response

        except Exception as e:
            _logger.error("❌ Auto-login failed: %s", str(e), exc_info=True)
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
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .error {{
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    display: inline-block;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    max-width: 500px;
                }}
                .error-icon {{
                    font-size: 60px;
                    margin-bottom: 20px;
                }}
                h2 {{ 
                    margin: 0 0 15px 0;
                    color: #333;
                }}
                p {{
                    color: #666;
                    margin: 0 0 25px 0;
                }}
                .retry {{
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    display: inline-block;
                }}
            </style>
        </head>
        <body>
            <div class="error">
                <div class="error-icon">❌</div>
                <h2>Auto Login Failed</h2>
                <p>{message}</p>
                <a href="/web/login" class="retry">Go to Login Page</a>
            </div>
        </body>
        </html>
        """
        return request.make_response(html_content, headers=[('Content-Type', 'text/html')])
