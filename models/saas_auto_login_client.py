# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
import secrets
from datetime import datetime, timedelta
import logging
_logger = logging.getLogger(__name__)

class SaasAutoLoginController(http.Controller):

    @http.route('/saas/generate_auth_link', type='json', auth='none', methods=['POST'], csrf=False)
    def generate_auth_link(self, user_id, admin_password, **kwargs):
        try:
            # تحقق من كلمة سر الأدمن
            admin = request.env['res.users'].sudo().search([('login', '=', 'admin')], limit=1)
            if not admin:
                return {'success': False, 'error': 'Admin not found'}

            try:
                admin.sudo()._check_credentials(admin_password, {'interactive': False})
            except:
                return {'success': False, 'error': 'Wrong admin password'}

            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                return {'success': False, 'error': 'User not found'}

            token = secrets.token_urlsafe(40)
            expires = datetime.now() + timedelta(minutes=10)

            request.env['ir.config_parameter'].sudo().set_param(
                f'saas.autologin.token.{token}',
                f'{user_id}|{expires.isoformat()}'
            )

            base = request.httprequest.host_url.rstrip('/')
            auth_url = f"{base}/saas/autologin?token={token}"

            return {
                'success': True,
                'auth_url': auth_url,
                'token': token,
                'expires_at': expires.isoformat()
            }

        except Exception as e:
            _logger.error("Generate link failed: %s", str(e))
            return {'success': False, 'error': str(e)}

    @http.route('/saas/autologin', type='http', auth='none', methods=['GET'], csrf=False)
    def autologin(self, token, **kwargs):
        try:
            data = request.env['ir.config_parameter'].sudo().get_param(f'saas.autologin.token.{token}')
            if not data:
                return request.render('web.login', {'error': 'رمز غير صالح أو منتهي'})

            user_id, expires_str = data.split('|')
            expires = datetime.fromisoformat(expires_str)

            if datetime.now() > expires:
                request.env['ir.config_parameter'].sudo().set_param(f'saas.autologin.token.{token}', False)
                return request.render('web.login', {'error': 'انتهت صلاحية الرمز'})

            user = request.env['res.users'].sudo().browse(int(user_id))
            if not user.exists() or not user.active:
                return request.render('web.login', {'error': 'المستخدم غير موجود أو غير مفعل'})

            # حذف التوكن (مرة واحدة فقط)
            request.env['ir.config_parameter'].sudo().set_param(f'saas.autologin.token.{token}', False)

            # الطريقة الصحيحة والوحيدة في Odoo 18
            request.session.uid = int(user_id)
            request.session.login = user.login
            request.session.session_token = secrets.token_urlsafe(40)
            request.update_env(user=int(user_id))  # السطر الذهبي

            _logger.info("Auto-login ناجح للمستخدم: %s (ID: %d)", user.login, user_id)

            return request.redirect('/web')

        except Exception as e:
            _logger.error("Auto-login فشل: %s", str(e))
            return request.render('web.login', {'error': 'فشل تسجيل الدخول التلقائي'})
