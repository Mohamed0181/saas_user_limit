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

            # --- We'll collect all session data inside the cursor, then use plain values after ---
            session_data = None
            with registry.cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})

                token_key = f"saas_auto_login_token_{token}"
                try:
                    token_data = env["ir.config_parameter"].sudo().get_param(token_key)
                except Exception as e:
                    _logger.error("❌ Failed to read token param: %s", str(e))
                    return self._error_response("Failed to validate token", show_login=True)

                if not token_data:
                    return self._error_response("Invalid or expired token", show_login=True)

                # Decode token: "user_id|expiry"
                try:
                    user_id_str, expiry_str = token_data.split('|')
                    user_id = int(user_id_str)
                    expiry = int(expiry_str)
                except Exception as e:
                    _logger.exception("❌ Invalid token format")
                    # remove token to be safe
                    env["ir.config_parameter"].sudo().set_param(token_key, False)
                    cr.commit()
                    return self._error_response("Invalid token format", show_login=True)

                # Expired?
                if int(time.time()) > expiry:
                    env["ir.config_parameter"].sudo().set_param(token_key, False)
                    cr.commit()
                    return self._error_response("Token expired, please regenerate", show_login=True)

                user = env["res.users"].sudo().browse(user_id)
                if not user.exists():
                    return self._error_response("User not found", show_login=True)

                if not user.active:
                    return self._error_response("Inactive user", show_login=True)

                # Read required simple values now (while cursor is open)
                try:
                    user_login = user.login
                except Exception:
                    # ensure we always read login while cursor is alive
                    user_login = env['res.users'].sudo().browse(user_id).login

                try:
                    # get user context in a safe way while cursor is open
                    user_context = dict(user.context_get() or {})
                except Exception as e:
                    _logger.warning("⚠️ Failed to fetch user context: %s", str(e))
                    user_context = {"lang": "en_US", "tz": "UTC", "uid": user_id}

                # Remove token (one-time use)
                try:
                    env["ir.config_parameter"].sudo().set_param(token_key, False)
                    cr.commit()
                except Exception as e:
                    _logger.warning("⚠️ Failed to delete token: %s", str(e))

                # prepare session data (plain Python types)
                session_data = {
                    "db": db_name,
                    "uid": user_id,
                    "login": user_login,
                    "context": user_context,
                    "create_time": int(time.time()),
                }

            # --- Outside cursor: only use plain values, never touch ORM recordsets ---
            if not session_data:
                return self._error_response("Failed to prepare session data", show_login=True)

            # Create session safely (no ORM access here)
            try:
                # clear previous session and set values
                request.session.clear()
                request.session.db = session_data["db"]
                request.session.uid = session_data["uid"]
                request.session.login = session_data["login"]
                # set context as a dict
                request.session.context = session_data["context"]
                # set create_time to satisfy Odoo session save check
                request.session["create_time"] = session_data["create_time"]
            except Exception as e:
                _logger.exception("❌ Failed to set request.session: %s", str(e))
                return self._error_response("Failed to create session", show_login=True)

            _logger.info("✅ Session created successfully for user: %s", session_data["login"])

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
