# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
import logging
import time
import werkzeug

_logger = logging.getLogger(__name__)


class SaasClientLoginController(http.Controller):
    """
    Controller يعمل في قاعدة بيانات العميل
    يستقبل الـ token ويسجل دخول المستخدم
    """

    @http.route('/saas/client_login/<string:token>', 
                type='http', auth='public', website=False, csrf=False)
    def client_auto_login(self, token, **kwargs):
        """
        تسجيل دخول تلقائي باستخدام الـ token
        """
        try:
            _logger.info("🔐 Client auto-login request received with token: %s...", token[:10])

            # قراءة الـ token من ir.config_parameter
            token_key = f'saas_auto_login_token_{token}'
            IrConfigParameter = request.env['ir.config_parameter'].sudo()
            
            token_data = IrConfigParameter.get_param(token_key)

            if not token_data:
                _logger.error("❌ Token not found or expired: %s", token[:10])
                return self._error_page('Invalid or expired login token', 401)

            # فك تشفير البيانات
            try:
                user_id, expiry = token_data.split('|')
                user_id = int(user_id)
                expiry = int(expiry)
            except ValueError:
                _logger.error("❌ Invalid token format")
                return self._error_page('Invalid token format', 400)

            # التحقق من انتهاء الصلاحية
            current_time = int(time.time())
            if current_time > expiry:
                _logger.error("❌ Token expired: %s", token[:10])
                # حذف الـ token المنتهي
                IrConfigParameter.set_param(token_key, False)
                return self._error_page('Login token has expired. Please try again.', 401)

            # جلب المستخدم
            user = request.env['res.users'].sudo().browse(user_id)

            if not user.exists():
                _logger.error("❌ User not found: ID %s", user_id)
                return self._error_page('User not found', 404)

            if not user.active:
                _logger.error("❌ User is inactive: %s (ID: %s)", user.name, user.id)
                return self._error_page(f'User {user.name} is inactive', 403)

            _logger.info("✅ User found: %s (ID: %s, Login: %s)", user.name, user.id, user.login)

            # حذف الـ token بعد الاستخدام (one-time use)
            IrConfigParameter.set_param(token_key, False)
            _logger.info("🗑️ Token deleted after use")

            # ✅ الحل الصحيح: إنشاء session جديدة
            # نحتاج لإنشاء session وتسجيل الدخول بشكل صحيح
            
            # 1. إنشاء session جديدة
            request.session.logout(keep_db=True)
            
            # 2. تسجيل الدخول باستخدام uid مباشرة
            request.session.uid = user_id
            request.session.login = user.login
            request.session.session_token = request.session.sid
            
            # 3. تحديث الـ context
            request.session.context = request.env['res.users'].context_get()
            
            # 4. حفظ الـ session
            request.session.touch()
            
            _logger.info("✅ Session created successfully for user: %s", user.login)
            
            # 5. Update user's login date
            user.sudo().write({'login_date': http.fields.Datetime.now()})

            # 6. إعادة التوجيه للـ dashboard
            response = werkzeug.utils.redirect('/web')
            
            # إضافة session cookie
            response.set_cookie(
                'session_id',
                request.session.sid,
                max_age=90 * 24 * 60 * 60,  # 90 days
                httponly=True,
                secure=False  # True if using HTTPS
            )
            
            return response

        except Exception as e:
            _logger.error("❌ Client auto-login failed: %s", str(e), exc_info=True)
            return self._error_page(f'Login failed: {str(e)}', 500)

    def _error_page(self, message, code):
        """عرض صفحة خطأ"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Login Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .error-container {{
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    max-width: 500px;
                    width: 100%;
                    text-align: center;
                }}
                .error-icon {{
                    font-size: 60px;
                    margin-bottom: 20px;
                    animation: shake 0.5s ease-in-out;
                }}
                @keyframes shake {{
                    0%, 100% {{ transform: translateX(0); }}
                    25% {{ transform: translateX(-10px); }}
                    75% {{ transform: translateX(10px); }}
                }}
                h1 {{
                    color: #d32f2f;
                    margin-bottom: 10px;
                    font-size: 24px;
                }}
                .error-code {{
                    color: #666;
                    font-size: 14px;
                    margin-bottom: 20px;
                }}
                .error-message {{
                    color: #555;
                    margin-bottom: 30px;
                    line-height: 1.6;
                    padding: 15px;
                    background: #f5f5f5;
                    border-radius: 8px;
                    border-left: 4px solid #d32f2f;
                    text-align: left;
                }}
                .btn {{
                    padding: 12px 30px;
                    text-decoration: none;
                    border-radius: 25px;
                    display: inline-block;
                    font-weight: 500;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    transition: all 0.3s;
                }}
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <div class="error-icon">🔒</div>
                <h1>Login Failed</h1>
                <div class="error-code">Error Code: {code}</div>
                <div class="error-message">{message}</div>
                <a href="javascript:window.close();" class="btn">Close Window</a>
            </div>
        </body>
        </html>
        """
        return request.make_response(
            html_content, 
            headers=[('Content-Type', 'text/html; charset=utf-8')]
        )
