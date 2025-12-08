# -*- coding: utf-8 -*-
# saas_auto_login_client/controllers/main.py

from odoo import http
from odoo.http import request
from odoo.addons.web.controllers.main import Home
import logging
import time
import werkzeug

_logger = logging.getLogger(__name__)


class SaasAutoLoginClientController(http.Controller):

    @http.route('/saas/client_login/<string:token>', type='http', auth='none', csrf=False, website=False)
    def client_auto_login(self, token, **kwargs):
        """
        تسجيل دخول تلقائي باستخدام token مؤقت
        """
        try:
            _logger.info("🔐 Received auto-login request with token: %s...", token[:10])

            # الحصول على db من الـ request
            db_name = request.session.db or request.db
            
            # إنشاء registry و cursor
            registry = http.Registry(db_name)
            with registry.cursor() as cr:
                env = http.Environment(cr, http.SUPERUSER_ID, {})
                
                # البحث عن الـ token في ir.config_parameter
                token_key = f'saas_auto_login_token_{token}'
                token_data = env['ir.config_parameter'].get_param(token_key)

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
                        _logger.error("❌ Token expired")
                        env['ir.config_parameter'].set_param(token_key, False)
                        cr.commit()
                        return self._error_response('Token expired. Please try again.')

                except ValueError as e:
                    _logger.error("❌ Invalid token format: %s", str(e))
                    return self._error_response('Invalid token format')

                # البحث عن المستخدم
                user = env['res.users'].browse(user_id)
                if not user.exists():
                    _logger.error("❌ User not found: ID %s", user_id)
                    return self._error_response('User not found')

                if not user.active:
                    _logger.error("❌ User inactive: %s", user.login)
                    return self._error_response('User is inactive')

                _logger.info("✅ Token validated for user: %s (ID: %s)", user.login, user.id)

                # حذف الـ token بعد الاستخدام
                env['ir.config_parameter'].set_param(token_key, False)
                cr.commit()

                # ✨ الحل النهائي: إنشاء session جديدة
                request.session.logout(keep_db=True)
                
                # تسجيل الدخول باستخدام uid مباشرة
                request.session.uid = user_id
                request.session.login = user.login
                request.session.db = db_name
                
                # الحصول على context
                with registry.cursor() as cr2:
                    env2 = http.Environment(cr2, user_id, {})
                    context = env2['res.users'].context_get()
                    request.session.context = context
                
                _logger.info("✅ Session created successfully for user: %s", user.login)

            # إعادة توجيه للصفحة الرئيسية
            return werkzeug.utils.redirect('/web')

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
                    animation: slideIn 0.3s ease-out;
                }}
                @keyframes slideIn {{
                    from {{
                        transform: translateY(-20px);
                        opacity: 0;
                    }}
                    to {{
                        transform: translateY(0);
                        opacity: 1;
                    }}
                }}
                .error-icon {{
                    font-size: 60px;
                    margin-bottom: 20px;
                }}
                h2 {{ 
                    margin: 0 0 15px 0;
                    color: #333;
                    font-size: 24px;
                }}
                p {{
                    color: #666;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 0 0 25px 0;
                }}
                .retry {{
                    margin-top: 20px;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    display: inline-block;
                    font-weight: 600;
                    transition: transform 0.2s, box-shadow 0.2s;
                }}
                .retry:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
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
