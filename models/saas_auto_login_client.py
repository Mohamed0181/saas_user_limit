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
        """Auto login controller (Odoo 18 Compatible)"""
        try:
            _logger.info("🔐 Auto-login request token=%s", token[:10])

            db_name = self._ensure_db()
            if not db_name:
                return self._error_response("Database not found", show_login=True)

            _logger.info("📊 Using DB: %s", db_name)

            # Registry loader for Odoo 18
            import odoo
            try:
                registry = odoo.modules.registry.Registry(db_name)
            except Exception as e:
                _logger.error("❌ Registry load failed: %s", str(e))
                return self._error_response(f"Database error: {str(e)}", show_login=True)

            # Read token from DB
            with registry.cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})

                token_key = f"saas_auto_login_token_{token}"
                token_data = env["ir.config_parameter"].sudo().get_param(token_key)

                if not token_data:
                    return self._error_response("Invalid or expired token", show_login=True)

                # Decode token: "user_id|expiry"
                try:
                    user_id, expiry = token_data.split('|')
                    user_id = int(user_id)
                    expiry = int(expiry)
                except:
                    env["ir.config_parameter"].sudo().set_param(token_key, False)
                    return self._error_response("Invalid token format", show_login=True)

                # Expired?
                if time.time() > expiry:
                    env["ir.config_parameter"].sudo().set_param(token_key, False)
                    return self._error_response("Token expired, please regenerate", show_login=True)

                user = env["res.users"].sudo().browse(user_id)
                if not user.exists():
                    return self._error_response("User not found", show_login=True)

                if not user.active:
                    return self._error_response("Inactive user", show_login=True)

                # Remove token (one-time use)
                env["ir.config_parameter"].sudo().set_param(token_key, False)
                cr.commit()

            # Create session safely
            self._create_user_session(env, user)

            return werkzeug.utils.redirect("/web")

        except Exception as e:
            _logger.error("❌ Auto-login failure: %s", str(e), exc_info=True)
            return self._error_response(str(e), show_login=True)

    # ----------------------------------------------------------------------
    # Detect DB
    # ----------------------------------------------------------------------
    def _ensure_db(self):
        db = request.session.db if hasattr(request, "session") else None

        if not db and hasattr(request, "db"):
            db = request.db

        if not db:
            import odoo
            dbs = odoo.service.db.list_dbs(True)
            if dbs:
                db = dbs[0]

        if db and hasattr(request, "session"):
            request.session.db = db

        return db

    # ----------------------------------------------------------------------
    # Create Session (Odoo 17 & 18 Safe)
    # ----------------------------------------------------------------------
    def _create_user_session(self, env, user):
        """Create session without cursor issues (Odoo 18 compatible)."""

        request.session.clear()

        request.session.db = env.cr.dbname
        request.session.uid = user.id
        request.session.login = user.login

        try:
            ctx = user.context_get()
            request.session.context = ctx
        except Exception as e:
            _logger.warning("⚠️ Failed to load context: %s", str(e))
            request.session.context = {
                "lang": "en_US",
                "tz": "UTC",
                "uid": user.id,
            }

        _logger.info("✅ Session created successfully for user: %s", user.login)

    # ----------------------------------------------------------------------
    # Error Page
    # ----------------------------------------------------------------------
    def _error_response(self, message, show_login=False):
        login_button = (
            '<a href="/web/login" class="btn btn-primary">Go to Login Page</a>'
            if show_login else ""
        )

        html = f"""
        <html>
        <head><meta charset="utf-8"><title>Auto Login Error</title></head>
        <body style="background:#f8f8f8;font-family:Arial;padding:50px;text-align:center;">
            <h1 style="color:#c00;">❌ Auto Login Failed</h1>
            <p style="background:#fff;padding:20px;border-radius:10px;display:inline-block;">
                {message}
            </p><br><br>
            {login_button}
            <a href="javascript:window.close();" class="btn btn-secondary">Close</a>
        </body>
        </html>
        """
        return request.make_response(html, headers=[("Content-Type", "text/html")])
