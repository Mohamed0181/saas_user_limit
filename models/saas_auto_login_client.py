from odoo import http
from odoo.http import request
import secrets
import string
from datetime import datetime, timedelta
import logging

_logger = logging.getLogger(__name__)


class SaasAutoLoginController(http.Controller):
    """
    This controller should be installed on client's Odoo database
    via the automatic module you mentioned.
    
    It provides auto-login functionality for SAAS management.
    """
    
    @http.route('/saas/generate_auth_link', type='json', auth='none', methods=['POST'], csrf=False)
    def generate_auth_link(self, user_id, admin_password, **kwargs):
        """
        Generate one-time authentication link for a user
        
        Args:
            user_id: ID of the user to login as
            admin_password: Admin password for verification
            
        Returns:
            dict: {
                'success': bool,
                'auth_url': str,
                'token': str,
                'expires_at': str
            }
        """
        try:
            # Verify admin password
            admin_user = request.env['res.users'].sudo().search([
                ('login', '=', 'admin')
            ], limit=1)
            
            if not admin_user:
                return {'success': False, 'error': 'Admin user not found'}
            
            # Verify password
            try:
                admin_user.sudo()._check_credentials(admin_password, {'interactive': False})
            except:
                return {'success': False, 'error': 'Invalid admin password'}
            
            # Get target user
            user = request.env['res.users'].sudo().browse(user_id)
            
            if not user.exists():
                return {'success': False, 'error': 'User not found'}
            
            # Generate secure token
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(minutes=5)
            
            # Store token in database (using ir.config_parameter or custom model)
            request.env['ir.config_parameter'].sudo().set_param(
                f'saas.autologin.token.{token}',
                f'{user_id}|{expires_at.isoformat()}'
            )
            
            # Build auth URL
            base_url = request.httprequest.host_url.rstrip('/')
            auth_url = f"{base_url}/saas/autologin?token={token}"
            
            _logger.info("✅ Auth link generated for user: %s (ID: %s)", user.login, user_id)
            
            return {
                'success': True,
                'auth_url': auth_url,
                'token': token,
                'expires_at': expires_at.isoformat()
            }
            
        except Exception as e:
            _logger.error("❌ Failed to generate auth link: %s", str(e))
            return {'success': False, 'error': str(e)}
    
    @http.route('/saas/autologin', type='http', auth='none', methods=['GET'], csrf=False)
    def autologin(self, token, **kwargs):
        """
        Auto-login endpoint using one-time token
        
        Args:
            token: One-time authentication token
            
        Returns:
            Redirect to /web with authenticated session
        """
        try:
            # Retrieve token data
            token_data = request.env['ir.config_parameter'].sudo().get_param(
                f'saas.autologin.token.{token}'
            )
            
            if not token_data:
                return request.render('web.login', {
                    'error': 'Invalid or expired token'
                })
            
            # Parse token data
            user_id_str, expires_at_str = token_data.split('|')
            user_id = int(user_id_str)
            expires_at = datetime.fromisoformat(expires_at_str)
            
            # Check expiration
            if datetime.now() > expires_at:
                # Delete expired token
                request.env['ir.config_parameter'].sudo().set_param(
                    f'saas.autologin.token.{token}',
                    False
                )
                return request.render('web.login', {
                    'error': 'Token has expired'
                })
            
            # Get user
            user = request.env['res.users'].sudo().browse(user_id)
            
            if not user.exists() or not user.active:
                return request.render('web.login', {
                    'error': 'User not found or inactive'
                })
            
            # Delete token (one-time use)
            request.env['ir.config_parameter'].sudo().set_param(
                f'saas.autologin.token.{token}',
                False
            )
            
            # Create session for user
            request.session.authenticate(
                request.env.cr.dbname,
                user.login,
                user.login,  # We use a trick here - see below
                user_agent_env=request.httprequest.user_agent
            )
            
            # Alternative: Direct session creation
            request.session.uid = user_id
            request.session.login = user.login
            request.session.session_token = secrets.token_urlsafe(32)
            request.env.user = user.sudo()
            
            _logger.info("✅ Auto-login successful for user: %s (ID: %s)", user.login, user_id)
            
            # Redirect to home
            return request.redirect('/web')
            
        except Exception as e:
            _logger.error("❌ Auto-login failed: %s", str(e))
            return request.render('web.login', {
                'error': f'Auto-login failed: {str(e)}'
            })
    
    @http.route('/saas/verify_token', type='json', auth='none', methods=['POST'], csrf=False)
    def verify_token(self, token, **kwargs):
        """Verify if a token is still valid"""
        try:
            token_data = request.env['ir.config_parameter'].sudo().get_param(
                f'saas.autologin.token.{token}'
            )
            
            if not token_data:
                return {'valid': False, 'error': 'Token not found'}
            
            user_id_str, expires_at_str = token_data.split('|')
            expires_at = datetime.fromisoformat(expires_at_str)
            
            if datetime.now() > expires_at:
                return {'valid': False, 'error': 'Token expired'}
            
            return {
                'valid': True,
                'user_id': int(user_id_str),
                'expires_at': expires_at_str
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
