# -*- coding: utf-8 -*-
"""
الحل النهائي المُصلح للـ Auto Login في Odoo 18/19
يعالج مشكلة session_token = None
"""
from odoo import http
from odoo.http import request
import logging
import time
import werkzeug
import secrets

_logger = logging.getLogger(__name__)


class SaasClientAutoLogin(http.Controller):

    @http.route('/saas/client_login/<string:token>', 
                type='http', auth='none', website=False, csrf=False, save_session=False)
    def auto_login(self, token, redirect='/web', **kw):
        """
        تسجيل الدخول التلقائي
        save_session=False مهم لتجنب مشاكل session_token
        """
        
        try:
            # ✅ 1. الحصول على اسم قاعدة البيانات
            db = request.httprequest.environ.get('HTTP_HOST', '').split(':')[0]
            
            # إذا لم ينجح، جرب من URL
            if not db:
                db = request.httprequest.host.split(':')[0]
            
            if not db:
                _logger.error("❌ Cannot determine database name")
                return self._render_error('Database not found')
            
            _logger.info("🔍 Database: %s, Token: %s...", db, token[:10])
            
            # ✅ 2. قراءة Token باستخدام cursor منفصل
            token_key = f'saas_auto_login_token_{token}'
            
            with request.env.registry.cursor() as cr:
                env = http.api.Environment(cr, http.SUPERUSER_ID, {})
                
                token_data = env['ir.config_parameter'].get_param(token_key)
                
                if not token_data:
                    _logger.error("❌ Token not found: %s", token[:10])
                    return self._render_error('Invalid or expired login token')
                
                # ✅ 3. فك البيانات
                try:
                    user_id, expiry = token_data.split('|')
                    user_id = int(user_id)
                    expiry = int(expiry)
                except ValueError:
                    _logger.error("❌ Invalid token format")
                    return self._render_error('Invalid token format')
                
                # ✅ 4. التحقق من الصلاحية
                if int(time.time()) > expiry:
                    _logger.error("❌ Token expired")
                    env['ir.config_parameter'].set_param(token_key, False)
                    cr.commit()
                    return self._render_error('Token expired. Please try again.')
                
                # ✅ 5. جلب المستخدم
                user = env['res.users'].browse(user_id)
                
                if not user.exists():
                    _logger.error("❌ User not found: %s", user_id)
                    return self._render_error('User not found')
                
                if not user.active:
                    _logger.error("❌ User inactive: %s", user.login)
                    return self._render_error('User is inactive')
                
                user_login = user.login
                
                # ✅ 6. حذف Token (one-time use)
                env['ir.config_parameter'].set_param(token_key, False)
                cr.commit()
                
                _logger.info("✅ Token validated for user: %s (ID: %s)", user_login, user_id)
            
            # ✅ 7. إنشاء session جديدة بشكل صحيح
            # نستخدم session جديدة كاملة
            
            # إعادة تعيين الـ session
            request.session.logout(keep_db=True)
            
            # تعيين بيانات المستخدم
            request.session.uid = user_id
            request.session.login = user_login
            request.session.db = db
            
            # ✅ إنشاء session_token جديد (هذا الحل للمشكلة!)
            request.session.session_token = secrets.token_urlsafe(32)
            
            # تحديث context
            request.session.context = request.env['res.users'].context_get()
            
            # حفظ الـ session
            request.session.touch()
            
            _logger.info("✅ Session created successfully for: %s", user_login)
            
            # ✅ 8. إنشاء response مع cookies
            response = werkzeug.utils.redirect(redirect, 303)
            
            # تعيين session cookie
            response.set_cookie(
                'session_id',
                request.session.sid,
                max_age=90 * 24 * 60 * 60,  # 90 يوم
                httponly=True,
                samesite='Lax'
            )
            
            _logger.info("✅ Redirecting to: %s", redirect)
            
            return response
            
        except Exception as e:
            _logger.error("❌ Auto-login error: %s", str(e), exc_info=True)
            return self._render_error(f'Login failed: {str(e)}')
    
    def _render_error(self, message):
        """عرض صفحة خطأ أنيقة"""
        return request.make_response(f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>خطأ في تسجيل الدخول</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            padding: 50px 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            text-align: center;
            animation: slideIn 0.4s ease-out;
        }}
        @keyframes slideIn {{
            from {{ opacity: 0; transform: translateY(-30px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .icon {{
            font-size: 72px;
            margin-bottom: 25px;
            animation: shake 0.5s ease-in-out;
        }}
        @keyframes shake {{
            0%, 100% {{ transform: translateX(0); }}
            25% {{ transform: translateX(-10px); }}
            75% {{ transform: translateX(10px); }}
        }}
        h1 {{
            color: #d32f2f;
            font-size: 32px;
            margin-bottom: 20px;
            font-weight: 700;
        }}
        .message {{
            color: #555;
            font-size: 18px;
            line-height: 1.8;
            margin-bottom: 35px;
            padding: 25px;
            background: linear-gradient(to right, #fff5f5, #fff);
            border-radius: 12px;
            border-right: 5px solid #d32f2f;
            text-align: right;
        }}
        .btn-group {{
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }}
        .btn {{
            padding: 15px 35px;
            text-decoration: none;
            border-radius: 30px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        .btn-primary:hover {{
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }}
        .btn-secondary {{
            background: #f5f5f5;
            color: #555;
        }}
        .btn-secondary:hover {{
            background: #e0e0e0;
            transform: translateY(-2px);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔒</div>
        <h1>فشل تسجيل الدخول</h1>
        <div class="message">{message}</div>
        <div class="btn-group">
            <button class="btn btn-secondary" onclick="window.close()">
                ✖️ إغلاق النافذة
            </button>
            <a href="/web/login" class="btn btn-primary">
                🔑 تسجيل الدخول يدوياً
            </a>
        </div>
    </div>
</body>
</html>
        """, headers=[('Content-Type', 'text/html; charset=utf-8')])
