# -*- coding: utf-8 -*-
from odoo import http, fields
from odoo.http import request
import logging
from datetime import datetime

_logger = logging.getLogger(__name__)


class SaasClientLoginController(http.Controller):
    """
    Controller الخاص بقاعدة بيانات العميل
    يستقبل الـ token ويقوم بتسجيل الدخول
    """

    @http.route('/saas/client_login/<string:token>', 
                type='http', auth='public', website=False, csrf=False)
    def client_auto_login(self, token, **kwargs):
        """
        استقبال الـ Token والتحقق منه وتسجيل دخول المستخدم
        """
        # الحصول على بيانات الـ request
        ip_address = request.httprequest.environ.get('REMOTE_ADDR', 'unknown')
        user_agent = request.httprequest.environ.get('HTTP_USER_AGENT', '')
        
        try:
            _logger.info("🔐 Client auto-login request received with token: %s...", token[:10])
            _logger.info("🌐 IP: %s", ip_address)

            # ✅ استخدام Token Manager للتحقق وتسجيل الدخول
            token_manager = request.env['saas.client.token.manager']
            result = token_manager.validate_and_login_user(token)

            # ✅ تسجيل المحاولة في Security Log (اختياري)
            self._log_login_attempt(result, token, ip_address, user_agent)

            if not result['success']:
                return self._handle_failed_login(result)

            # ✅ تسجيل الدخول للمستخدم
            user = result['user']
            
            try:
                _logger.info("🔑 Creating session for user: %s (ID: %s)", user.login, user.id)
                
                # ✅ الطريقة الصحيحة لـ Odoo 18 - بدون استخدام authenticate
                # إنشاء الـ session مباشرة
                request.session.uid = user.id
                request.session.login = user.login
                request.session.db = request.env.cr.dbname
                
                # تعيين الـ session token
                if not request.session.sid:
                    request.session.rotate = True
                
                # الحصول على context المستخدم
                with request.env.cr.savepoint():
                    user_rec = request.env['res.users'].sudo().browse(user.id)
                    context = user_rec.context_get() or {}
                    request.session.context = dict(context)
                
                # حفظ الـ session
                request.session.save()
                
                # تحديث الـ environment
                request.update_env(user=user.id)
                
                _logger.info("✅ Session created successfully for user: %s", user.login)
                
                # تحديث last login
                request.env['res.users'].sudo().browse(user.id).write({
                    'login_date': fields.Datetime.now()
                })

            except Exception as e:
                _logger.error("❌ Failed to create session: %s", str(e), exc_info=True)
                return self._error_page(f'Failed to create user session: {str(e)}', 500)

            # ✅ تحديد صفحة الـ redirect حسب نوع المستخدم
            redirect_url = self._get_redirect_url(user)
            
            _logger.info("🔗 Redirecting to: %s", redirect_url)
            
            # عرض صفحة نجاح مع auto-redirect
            return self._success_page(user, redirect_url)

        except Exception as e:
            _logger.error("❌ Client auto-login failed: %s", str(e), exc_info=True)
            return self._error_page(f'Auto-login failed: {str(e)}', 500)

    def _log_login_attempt(self, result, token, ip_address, user_agent):
        """تسجيل محاولة الدخول في Security Log"""
        try:
            security_log = request.env['saas.client.security.log']
            
            if result['success']:
                login_type = 'auto_login_success'
                user_id = result['user_id']
                error_message = None
            else:
                reason = result['reason']
                login_type_map = {
                    'expired': 'token_expired',
                    'not_found': 'token_invalid',
                    'invalid_format': 'token_invalid',
                    'user_not_found': 'auto_login_failed',
                    'user_inactive': 'user_inactive',
                }
                login_type = login_type_map.get(reason, 'auto_login_failed')
                user_id = result.get('user_id')
                error_message = f"Reason: {reason}"

            security_log.log_attempt(
                user_id=user_id,
                login_type=login_type,
                success=result['success'],
                ip_address=ip_address,
                user_agent=user_agent,
                token_hash=token[:10] + '...',
                error_message=error_message
            )
        except:
            pass  # لا نريد أن يفشل الـ login بسبب فشل الـ logging

    def _handle_failed_login(self, result):
        """معالجة فشل تسجيل الدخول"""
        reason = result['reason']
        
        error_messages = {
            'invalid_format': ('Invalid token format', 400),
            'not_found': ('Invalid or expired token', 401),
            'expired': ('Token has expired. Please request a new login link.', 401),
            'user_not_found': ('User not found', 404),
            'user_inactive': (f"User {result.get('user_name', 'Unknown')} is inactive", 403),
            'parse_error': (f"Token data error: {result.get('error', 'Unknown')}", 400),
        }
        
        message, code = error_messages.get(reason, ('Authentication failed', 401))
        return self._error_page(message, code)

    def _get_redirect_url(self, user):
        """تحديد URL الـ redirect حسب نوع المستخدم"""
        
        # يمكنك تخصيص الـ redirect حسب المجموعات
        if user.has_group('base.group_system'):
            return '/web'
        elif user.has_group('sales_team.group_sale_manager'):
            return '/web#action=sale.action_orders'
        elif user.has_group('sales_team.group_sale_salesman'):
            return '/web#action=sale.action_quotations'
        elif user.has_group('account.group_account_manager'):
            return '/web#action=account.action_move_out_invoice_type'
        elif user.has_group('purchase.group_purchase_user'):
            return '/web#action=purchase.purchase_rfq'
        
        # Default redirect
        return '/web'

    def _success_page(self, user, redirect_url):
        """عرض صفحة نجاح تسجيل الدخول مع auto-redirect"""
        
        # إضافة session_id للـ redirect URL
        session_id = request.session.sid
        separator = '&' if '#' in redirect_url or '?' in redirect_url else '?'
        full_redirect_url = f"{redirect_url}{separator}session_id={session_id}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Login Successful</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta http-equiv="refresh" content="1;url={full_redirect_url}">
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
                .success-container {{
                    background: white;
                    padding: 50px 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    max-width: 500px;
                    width: 100%;
                    text-align: center;
                    animation: slideIn 0.4s ease-out;
                }}
                @keyframes slideIn {{
                    from {{
                        opacity: 0;
                        transform: translateY(-30px) scale(0.95);
                    }}
                    to {{
                        opacity: 1;
                        transform: translateY(0) scale(1);
                    }}
                }}
                .success-icon {{
                    font-size: 70px;
                    margin-bottom: 25px;
                    animation: bounce 0.6s ease-in-out;
                }}
                @keyframes bounce {{
                    0%, 100% {{ transform: translateY(0); }}
                    50% {{ transform: translateY(-15px); }}
                }}
                h1 {{
                    color: #4caf50;
                    margin-bottom: 15px;
                    font-size: 28px;
                    font-weight: 600;
                }}
                .welcome-message {{
                    color: #666;
                    margin-bottom: 10px;
                    font-size: 18px;
                }}
                .user-name {{
                    color: #333;
                    font-weight: 600;
                    font-size: 20px;
                    margin-bottom: 20px;
                }}
                .loader {{
                    margin: 25px auto;
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #667eea;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
                .redirect-message {{
                    color: #888;
                    font-size: 14px;
                    margin-top: 20px;
                    padding: 15px;
                    background: #f5f5f5;
                    border-radius: 8px;
                    border-left: 4px solid #4caf50;
                }}
                .manual-link {{
                    display: inline-block;
                    margin-top: 20px;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: 500;
                    transition: all 0.3s;
                }}
                .manual-link:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }}
            </style>
        </head>
        <body>
            <div class="success-container">
                <div class="success-icon">✅</div>
                <h1>Login Successful!</h1>
                <div class="welcome-message">Welcome back,</div>
                <div class="user-name">{user.name}</div>
                <div class="loader"></div>
                <div class="redirect-message">
                    Redirecting you to the dashboard...<br>
                    Please wait a moment.
                </div>
                <a href="{full_redirect_url}" class="manual-link">
                    Click here if not redirected
                </a>
            </div>
        </body>
        </html>
        """
        return request.make_response(
            html_content,
            headers=[
                ('Content-Type', 'text/html; charset=utf-8'),
                ('Cache-Control', 'no-cache, no-store, must-revalidate'),
                ('Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly; SameSite=Lax')
            ]
        )

    def _error_page(self, message, code):
        """عرض صفحة خطأ"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Login Failed</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #f85032 0%, #e73827 100%);
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
                    animation: slideIn 0.3s ease-out;
                }}
                @keyframes slideIn {{
                    from {{
                        opacity: 0;
                        transform: translateY(-20px);
                    }}
                    to {{
                        opacity: 1;
                        transform: translateY(0);
                    }}
                }}
                .error-icon {{
                    font-size: 60px;
                    margin-bottom: 20px;
                    animation: shake 0.5s ease-in-out;
                }}
                @keyframes shake {{
                    0%, 100% {{ transform: translateX(0); }}
                    25% {{ transform: translateX(-10px); }}
                    50% {{ transform: translateX(10px); }}
                    75% {{ transform: translateX(-10px); }}
                }}
                h1 {{
                    color: #e53935;
                    margin-bottom: 15px;
                    font-size: 28px;
                    font-weight: 600;
                }}
                .error-code {{
                    color: #999;
                    font-size: 14px;
                    margin-bottom: 20px;
                    font-family: monospace;
                }}
                .error-message {{
                    color: #555;
                    font-size: 16px;
                    line-height: 1.6;
                    margin-bottom: 30px;
                    padding: 20px;
                    background: #fff3f3;
                    border-radius: 8px;
                    border-left: 4px solid #e53935;
                }}
                .help-section {{
                    background: #f5f5f5;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
                .help-section h3 {{
                    color: #666;
                    font-size: 14px;
                    margin-bottom: 10px;
                    font-weight: 500;
                }}
                .help-section p {{
                    color: #888;
                    font-size: 13px;
                    line-height: 1.5;
                }}
                .action-button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: 500;
                    transition: all 0.3s;
                    margin: 5px;
                }}
                .action-button:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }}
                .timestamp {{
                    color: #aaa;
                    font-size: 12px;
                    margin-top: 20px;
                    font-family: monospace;
                }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <div class="error-icon">❌</div>
                <h1>Login Failed</h1>
                <div class="error-code">Error Code: {code}</div>
                <div class="error-message">
                    {message}
                </div>
                <div class="help-section">
                    <h3>💡 Need help?</h3>
                    <p>Please request a new login link from your administrator.</p>
                </div>
                <a href="/web/login" class="action-button">Go to Login Page</a>
                <div class="timestamp">Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
        </body>
        </html>
        """
        return request.make_response(
            html_content,
            headers=[
                ('Content-Type', 'text/html; charset=utf-8'),
                ('Cache-Control', 'no-cache, no-store, must-revalidate')
            ],
            status=code
        )
