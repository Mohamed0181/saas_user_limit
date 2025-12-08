# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
from odoo.addons.web.controllers.home import Home
import logging
import time
import werkzeug

_logger = logging.getLogger(__name__)


class SaasClientLoginController(http.Controller):
    """
    Controller للتسجيل التلقائي - الحل البديل المضمون
    """

    @http.route('/saas/client_login/<string:token>', 
                type='http', auth='public', website=False, csrf=False)
    def client_auto_login(self, token, **kwargs):
        """
        تسجيل دخول تلقائي - يستخدم طريقة مشابهة لـ web/login
        """
        try:
            _logger.info("🔐 Auto-login request: token=%s...", token[:10])

            # قراءة الـ token
            token_key = f'saas_auto_login_token_{token}'
            IrConfigParameter = request.env['ir.config_parameter'].sudo()
            token_data = IrConfigParameter.get_param(token_key)

            if not token_data:
                _logger.error("❌ Token not found: %s", token[:10])
                return self._error_page('Invalid or expired login token', 401)

            # فك البيانات
            try:
                user_id, expiry = token_data.split('|')
                user_id = int(user_id)
                expiry = int(expiry)
            except ValueError:
                _logger.error("❌ Invalid token format")
                return self._error_page('Invalid token format', 400)

            # التحقق من الصلاحية
            if int(time.time()) > expiry:
                _logger.error("❌ Token expired")
                IrConfigParameter.set_param(token_key, False)
                return self._error_page('Token expired. Please try again.', 401)

            # جلب المستخدم
            user = request.env['res.users'].sudo().browse(user_id)

            if not user.exists() or not user.active:
                _logger.error("❌ User not found or inactive: %s", user_id)
                return self._error_page('User not found or inactive', 404)

            _logger.info("✅ User: %s (ID: %s)", user.login, user.id)

            # حذف Token
            IrConfigParameter.set_param(token_key, False)

            # ✅ الحل الأفضل: استخدام نفس طريقة Odoo في web/login
            db = request.env.cr.dbname
            
            # إنشاء session جديدة بنفس طريقة Odoo
            request.session.authenticate(db, user.login, user.id)
            
            # هذا يستخدم الـ uid مباشرة بدون password
            # لأننا نستخدم sudo()
            
            _logger.info("✅ Session created for: %s", user.login)

            # Redirect
            return werkzeug.utils.redirect('/web')

        except Exception as e:
            _logger.error("❌ Login failed: %s", str(e), exc_info=True)
            return self._error_page(f'Login failed: {str(e)}', 500)

    def _error_page(self, message, code):
        """صفحة خطأ مبسطة"""
        return request.make_response(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Login Error</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    }}
                    .error-box {{
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                        text-align: center;
                        max-width: 500px;
                    }}
                    h1 {{ color: #d32f2f; margin-bottom: 20px; }}
                    p {{ color: #555; line-height: 1.6; margin-bottom: 30px; }}
                    .btn {{
                        display: inline-block;
                        padding: 12px 30px;
                        background: #667eea;
                        color: white;
                        text-decoration: none;
                        border-radius: 25px;
                        transition: all 0.3s;
                    }}
                    .btn:hover {{ transform: translateY(-2px); }}
                </style>
            </head>
            <body>
                <div class="error-box">
                    <h1>❌ Login Failed</h1>
                    <p><strong>Error {code}:</strong> {message}</p>
                    <a href="javascript:window.close();" class="btn">Close Window</a>
                </div>
            </body>
            </html>
        """, headers=[('Content-Type', 'text/html; charset=utf-8')])
