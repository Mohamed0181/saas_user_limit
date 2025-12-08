# -*- coding: utf-8 -*-
# saas_auto_login_client/controllers/main.py

from odoo import http
from odoo.http import request
import logging
import time
import werkzeug

_logger = logging.getLogger(__name__)


class SaasAutoLoginClientController(http.Controller):

    @http.route('/saas/client_login/<string:token>', 
                type='http', auth='none', csrf=False, website=False)
    def client_auto_login(self, token, **kwargs):
        """
        تسجيل دخول تلقائي باستخدام token مؤقت
        هذا الـ controller يعمل في قاعدة بيانات العميل
        """
        try:
            _logger.info("🔐 Received auto-login request with token: %s...", token[:10])
            
            # التأكد من وجود database
            db_name = self._ensure_db()
            if not db_name:
                return self._error_response('Database not found', show_login=True)
            
            _logger.info("📊 Using database: %s", db_name)
            
            # الحصول على registry
            import odoo
            try:
                registry = odoo.registry(db_name)
            except Exception as e:
                _logger.error("❌ Failed to get registry: %s", str(e))
                return self._error_response(f'Database error: {str(e)}', show_login=True)
            
            # البحث عن الـ token والتحقق منه
            with registry.cursor() as cr:
                from odoo import SUPERUSER_ID
                env = odoo.api.Environment(cr, SUPERUSER_ID, {})
                
                # البحث عن الـ token
                token_key = f'saas_auto_login_token_{token}'
                
                try:
                    token_data = env['ir.config_parameter'].get_param(token_key)
                except Exception as e:
                    _logger.error("❌ Failed to get token: %s", str(e))
                    return self._error_response('Failed to validate token', show_login=True)

                if not token_data:
                    _logger.error("❌ Token not found: %s", token_key)
                    return self._error_response('Invalid or expired token. Please try again.', show_login=True)

                # فك تشفير الـ token
                try:
                    user_id, expiry = token_data.split('|')
                    user_id = int(user_id)
                    expiry = int(expiry)
                except ValueError as e:
                    _logger.error("❌ Invalid token format: %s", str(e))
                    env['ir.config_parameter'].set_param(token_key, False)
                    cr.commit()
                    return self._error_response('Invalid token format', show_login=True)

                # تحقق من انتهاء الصلاحية
                current_time = int(time.time())
                if current_time > expiry:
                    _logger.error("❌ Token expired (current: %s, expiry: %s)", current_time, expiry)
                    env['ir.config_parameter'].set_param(token_key, False)
                    cr.commit()
                    return self._error_response(
                        'Token expired. Please generate a new login link.',
                        show_login=True
                    )

                # البحث عن المستخدم
                try:
                    user = env['res.users'].browse(user_id)
                except Exception as e:
                    _logger.error("❌ Failed to browse user: %s", str(e))
                    return self._error_response('Failed to load user', show_login=True)
                
                if not user.exists():
                    _logger.error("❌ User not found: ID %s", user_id)
                    return self._error_response('User not found', show_login=True)
                
                if not user.active:
                    _logger.error("❌ User inactive: %s (ID: %s)", user.login, user.id)
                    return self._error_response(
                        f'User {user.name} is inactive. Please contact your administrator.',
                        show_login=True
                    )

                _logger.info("✅ User validated: %s (ID: %s)", user.login, user.id)

                # حذف الـ token (استخدام واحد فقط)
                try:
                    env['ir.config_parameter'].set_param(token_key, False)
                    cr.commit()
                    _logger.info("✅ Token deleted successfully")
                except Exception as e:
                    _logger.warning("⚠️ Failed to delete token: %s", str(e))
                
            # إنشاء session جديدة
            try:
                self._create_user_session(db_name, user_id, user.login, registry)
            except Exception as e:
                _logger.error("❌ Failed to create session: %s", str(e), exc_info=True)
                return self._error_response(f'Failed to create session: {str(e)}', show_login=True)
            
            _logger.info("✅ Session created successfully for user: %s", user.login)
            
            # إعادة التوجيه للصفحة الرئيسية
            return werkzeug.utils.redirect('/web')

        except Exception as e:
            _logger.error("❌ Auto-login failed: %s", str(e), exc_info=True)
            return self._error_response(f'Unexpected error: {str(e)}', show_login=True)

    def _ensure_db(self):
        """التأكد من وجود database"""
        db_name = None
        
        # محاولة الحصول على db من session
        if hasattr(request, 'session') and request.session.db:
            db_name = request.session.db
        # محاولة الحصول على db من request
        elif hasattr(request, 'db') and request.db:
            db_name = request.db
        # محاولة الحصول على db من httprequest
        elif hasattr(request, 'httprequest'):
            db_name = request.httprequest.environ.get('HTTP_X_OPENERP_DBFILTER')
            if not db_name:
                # استخدام database filter من config
                import odoo
                db_name = odoo.tools.config.get('dbfilter')
                if db_name:
                    # إذا كان dbfilter regex، نحاول الحصول على أول database متطابقة
                    import re
                    dbs = odoo.service.db.list_dbs(True)
                    for d in dbs:
                        if re.match(db_name, d):
                            db_name = d
                            break
        
        # إذا لم نجد، نحاول الحصول على أول database متاحة
        if not db_name:
            import odoo
            dbs = odoo.service.db.list_dbs(True)
            if dbs:
                db_name = dbs[0]
        
        # تعيين db في session
        if db_name and hasattr(request, 'session'):
            request.session.db = db_name
            
        return db_name

    def _create_user_session(self, db_name, user_id, user_login, registry):
        """إنشاء session للمستخدم"""
        import odoo
        
        # مسح الـ session القديمة
        if hasattr(request, 'session'):
            request.session.clear()
            
            # تعيين البيانات الأساسية
            request.session.db = db_name
            request.session.uid = user_id
            request.session.login = user_login
            
            # الحصول على context
            with registry.cursor() as cr:
                env = odoo.api.Environment(cr, user_id, {})
                try:
                    context = dict(env['res.users'].context_get())
                    request.session.context = context
                except Exception as e:
                    _logger.warning("⚠️ Failed to get user context: %s", str(e))
                    request.session.context = {
                        'lang': 'en_US',
                        'tz': 'UTC',
                        'uid': user_id,
                    }
            
            _logger.info("✅ Session data set: db=%s, uid=%s, login=%s", db_name, user_id, user_login)
        else:
            raise Exception("No session available")

    def _error_response(self, message, show_login=False):
        """صفحة خطأ محسنة"""
        login_button = ''
        if show_login:
            login_button = '<a href="/web/login" class="btn btn-primary">Go to Login Page</a>'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Auto Login Error</title>
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
                h2 {{
                    color: #d32f2f;
                    margin-bottom: 15px;
                    font-size: 24px;
                }}
                .error-message {{
                    color: #555;
                    margin-bottom: 30px;
                    line-height: 1.6;
                    padding: 15px;
                    background: #f5f5f5;
                    border-radius: 8px;
                    border-left: 4px solid #d32f2f;
                }}
                .btn {{
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    display: inline-block;
                    margin: 5px;
                    transition: all 0.3s;
                }}
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }}
                .btn-secondary {{
                    background: #6c757d;
                }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <div class="error-icon">❌</div>
                <h2>Auto Login Failed</h2>
                <div class="error-message">{message}</div>
                <div>
                    {login_button}
                    <a href="javascript:window.close();" class="btn btn-secondary">Close Window</a>
                </div>
            </div>
        </body>
        </html>
        """
        return request.make_response(html_content, headers=[('Content-Type', 'text/html; charset=utf-8')])
