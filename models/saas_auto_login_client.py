# ملف اسمه: /custom_addons/saas_core_login/controllers/client_login.py
# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
import logging, time, secrets

_logger = logging.getLogger(__name__)

class SaasCoreAutoLogin(http.Controller):

    @http.route('/saas/client_login/<string:token>', type='http', auth='none', csrf=False, save_session=False)
    def client_login(self, token, redirect='/web', **kw):
        try:
            db = request.db or request.httprequest.host.split(':')[0]
            if not db:
                return "Database not found", 400

            token_key = f'saas_auto_login_token_{token}'
            
            with request.env.registry.cursor() as cr:
                env = http.api.Environment(cr, http.SUPERUSER_ID, {})
                token_data = env['ir.config_parameter'].sudo().get_param(token_key)
                
                if not token_data or '|' not in token_data:
                    return "Invalid token", 401
                    
                user_id, expiry = token_data.split('|', 1)
                user_id, expiry = int(user_id), int(expiry)
                
                if time.time() > expiry:
                    env['ir.config_parameter'].sudo().set_param(token_key, False)
                    cr.commit()
                    return "Token expired", 410
                
                user = env['res.users'].sudo().browse(user_id)
                if not user.exists() or not user.active:
                    return "User invalid", 403
                
                # الحل السحري لـ Odoo 18/19
                request.session.logout(keep_db=True)
                request.session.uid = user_id
                request.session.login = user.login
                request.session.session_token = secrets.token_urlsafe(32)
                request.session.touch()
                
                # حذف التوكن بعد الاستخدام
                env['ir.config_parameter'].sudo().set_param(token_key, False)
                cr.commit()
                
                response = werkzeug.utils.redirect(redirect, 303)
                response.set_cookie('session_id', request.session.sid, max_age=90*24*60*60, httponly=True, samesite='Lax')
                return response
                
        except Exception as e:
            _logger.error("SaaS Core Login failed: %s", e, exc_info=True)
            return "Login failed", 500
