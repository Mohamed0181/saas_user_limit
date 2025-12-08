# -*- coding: utf-8 -*-
from odoo import api, fields, models, _
from odoo.exceptions import UserError
import logging
import json
import time

_logger = logging.getLogger(__name__)


class SaasClientTokenManager(models.AbstractModel):
    """
    Model مساعد لإدارة الـ Tokens في قاعدة بيانات العميل
    """
    _name = 'saas.client.token.manager'
    _description = 'SaaS Client Token Manager'

    @api.model
    def validate_token(self, token):
        """
        التحقق من صحة الـ Token وإرجاع بياناته
        
        :param token: الـ token المراد التحقق منه
        :return: dict مع بيانات المستخدم أو False
        """
        if not token or len(token) < 32:
            _logger.warning("⚠️ Invalid token format")
            return {'valid': False, 'reason': 'invalid_format'}

        token_key = f'saas_auto_login_token_{token}'
        config_param = self.env['ir.config_parameter'].sudo()
        token_data_str = config_param.get_param(token_key)

        if not token_data_str:
            _logger.warning("⚠️ Token not found: %s...", token[:10])
            return {'valid': False, 'reason': 'not_found'}

        try:
            # Parse token data (support both new and old format)
            token_data = self._parse_token_data(token_data_str)
            
            # التحقق من انتهاء الصلاحية
            current_time = int(time.time())
            if current_time > token_data['expiry']:
                _logger.warning("⚠️ Token expired: %s...", token[:10])
                # حذف الـ token المنتهي
                config_param.set_param(token_key, False)
                return {'valid': False, 'reason': 'expired'}

            _logger.info("✅ Token validated successfully for user_id: %s", token_data['user_id'])
            
            return {
                'valid': True,
                'user_id': token_data['user_id'],
                'token_key': token_key,
                'metadata': token_data.get('metadata', {})
            }

        except Exception as e:
            _logger.error("❌ Failed to validate token: %s", str(e))
            return {'valid': False, 'reason': 'parse_error', 'error': str(e)}

    @api.model
    def _parse_token_data(self, token_data_str):
        """
        تحليل بيانات الـ Token مع دعم الـ format القديم والجديد
        
        :param token_data_str: النص المحفوظ في ir.config_parameter
        :return: dict مع البيانات المحللة
        """
        try:
            # محاولة parse كـ JSON (format جديد)
            token_data = json.loads(token_data_str)
            if isinstance(token_data, dict):
                return token_data
        except (json.JSONDecodeError, ValueError):
            pass

        # Format قديم: "user_id|expiry"
        try:
            parts = token_data_str.split('|')
            if len(parts) == 2:
                return {
                    'user_id': int(parts[0]),
                    'expiry': int(parts[1]),
                    'metadata': {}
                }
        except (ValueError, IndexError):
            pass

        raise ValueError("Invalid token data format")

    @api.model
    def delete_token(self, token_key):
        """
        حذف Token بعد الاستخدام
        
        :param token_key: مفتاح الـ token في ir.config_parameter
        """
        try:
            self.env['ir.config_parameter'].sudo().set_param(token_key, False)
            _logger.info("🗑️ Token deleted: %s", token_key)
            return True
        except Exception as e:
            _logger.error("❌ Failed to delete token: %s", str(e))
            return False

    @api.model
    def cleanup_expired_tokens(self):
        """
        تنظيف جميع الـ Tokens المنتهية
        يتم استدعاؤه من Cron Job
        
        :return: عدد الـ tokens المحذوفة
        """
        _logger.info("🧹 Starting cleanup of expired tokens...")
        
        try:
            config_param = self.env['ir.config_parameter'].sudo()
            
            # البحث عن جميع tokens
            all_tokens = config_param.search([
                ('key', 'like', 'saas_auto_login_token_%')
            ])
            
            current_time = int(time.time())
            expired_count = 0
            error_count = 0
            
            for token_param in all_tokens:
                try:
                    token_data = self._parse_token_data(token_param.value)
                    
                    if token_data['expiry'] < current_time:
                        token_param.unlink()
                        expired_count += 1
                        
                except ValueError:
                    # Token بـ format خاطئ - حذفه
                    _logger.warning("⚠️ Deleting token with invalid format: %s", token_param.key)
                    token_param.unlink()
                    error_count += 1
                except Exception as e:
                    _logger.error("❌ Error processing token %s: %s", token_param.key, str(e))
            
            _logger.info(
                "✅ Cleanup completed: %s expired, %s errors, %s total processed",
                expired_count,
                error_count,
                len(all_tokens)
            )
            
            return {
                'expired': expired_count,
                'errors': error_count,
                'total': len(all_tokens)
            }
            
        except Exception as e:
            _logger.error("❌ Cleanup failed: %s", str(e), exc_info=True)
            return {'expired': 0, 'errors': 0, 'total': 0, 'error': str(e)}

    @api.model
    def get_token_stats(self):
        """
        الحصول على إحصائيات الـ Tokens الحالية
        
        :return: dict مع الإحصائيات
        """
        try:
            config_param = self.env['ir.config_parameter'].sudo()
            all_tokens = config_param.search([
                ('key', 'like', 'saas_auto_login_token_%')
            ])
            
            current_time = int(time.time())
            active_count = 0
            expired_count = 0
            
            for token_param in all_tokens:
                try:
                    token_data = self._parse_token_data(token_param.value)
                    if token_data['expiry'] >= current_time:
                        active_count += 1
                    else:
                        expired_count += 1
                except:
                    expired_count += 1
            
            return {
                'total': len(all_tokens),
                'active': active_count,
                'expired': expired_count
            }
            
        except Exception as e:
            _logger.error("❌ Failed to get token stats: %s", str(e))
            return {'total': 0, 'active': 0, 'expired': 0, 'error': str(e)}

    @api.model
    def validate_and_login_user(self, token):
        """
        التحقق من الـ Token وتسجيل دخول المستخدم
        دالة مركزية تجمع كل العمليات
        
        :param token: الـ token
        :return: dict مع النتيجة
        """
        # التحقق من الـ token
        validation_result = self.validate_token(token)
        
        if not validation_result['valid']:
            return {
                'success': False,
                'reason': validation_result['reason'],
                'error': validation_result.get('error')
            }
        
        user_id = validation_result['user_id']
        token_key = validation_result['token_key']
        
        # جلب بيانات المستخدم
        user = self.env['res.users'].sudo().browse(user_id)
        
        if not user.exists():
            _logger.error("❌ User not found: %s", user_id)
            self.delete_token(token_key)
            return {
                'success': False,
                'reason': 'user_not_found',
                'user_id': user_id
            }
        
        if not user.active:
            _logger.error("❌ User is inactive: %s", user.login)
            return {
                'success': False,
                'reason': 'user_inactive',
                'user_name': user.name
            }
        
        # حذف الـ token (single-use)
        self.delete_token(token_key)
        
        return {
            'success': True,
            'user': user,
            'user_id': user.id,
            'user_name': user.name,
            'user_login': user.login
        }


class SaasClientSecurityLog(models.Model):
    """
    Model لتسجيل محاولات تسجيل الدخول (اختياري - للأمان الإضافي)
    """
    _name = 'saas.client.security.log'
    _description = 'SaaS Client Security Log'
    _order = 'create_date desc'
    _rec_name = 'user_id'

    user_id = fields.Many2one(
        'res.users',
        string='User',
        ondelete='set null'
    )

    login_type = fields.Selection([
        ('auto_login_success', 'Auto Login - Success'),
        ('auto_login_failed', 'Auto Login - Failed'),
        ('token_expired', 'Token Expired'),
        ('token_invalid', 'Token Invalid'),
        ('user_inactive', 'User Inactive'),
    ], string='Type', required=True)

    ip_address = fields.Char(string='IP Address')
    
    user_agent = fields.Text(string='User Agent')
    
    token_hash = fields.Char(
        string='Token Hash',
        help='First 10 characters of token for tracking'
    )
    
    success = fields.Boolean(string='Success', default=False)
    
    error_message = fields.Text(string='Error Message')
    
    metadata = fields.Text(string='Metadata (JSON)')

    @api.model
    def log_attempt(self, user_id, login_type, success=False, **kwargs):
        """
        تسجيل محاولة تسجيل دخول
        
        :param user_id: ID المستخدم
        :param login_type: نوع محاولة الدخول
        :param success: نجحت أم لا
        :param kwargs: بيانات إضافية
        """
        try:
            values = {
                'user_id': user_id if isinstance(user_id, int) else False,
                'login_type': login_type,
                'success': success,
                'ip_address': kwargs.get('ip_address'),
                'user_agent': kwargs.get('user_agent'),
                'token_hash': kwargs.get('token_hash'),
                'error_message': kwargs.get('error_message'),
                'metadata': json.dumps(kwargs.get('metadata', {}))
            }
            
            self.sudo().create(values)
            
        except Exception as e:
            _logger.error("❌ Failed to log security event: %s", str(e))

    @api.model
    def cleanup_old_logs(self, days=30):
        """
        حذف السجلات القديمة
        
        :param days: عدد الأيام للحفاظ على السجلات
        """
        try:
            from datetime import datetime, timedelta
            
            cutoff_date = datetime.now() - timedelta(days=days)
            
            old_logs = self.search([
                ('create_date', '<', cutoff_date.strftime('%Y-%m-%d %H:%M:%S'))
            ])
            
            count = len(old_logs)
            old_logs.unlink()
            
            _logger.info("🧹 Cleaned up %s old security logs", count)
            return count
            
        except Exception as e:
            _logger.error("❌ Failed to cleanup old logs: %s", str(e))
            return 0
