# models/storage_quota_enforcer.py
# حل بدون XML - يمنع العميل مباشرة

from odoo import models, api, _
from odoo.exceptions import AccessError, UserError
import logging

_logger = logging.getLogger(__name__)


class BaseModelStorageEnforcer(models.AbstractModel):
    """
    Block all write operations when storage quota exceeded
    NO XML NEEDED - Pure Python Solution
    """
    _inherit = 'base'

    @api.model
    def _check_storage_quota_before_write(self):
        """Check storage quota and block if exceeded"""
        try:
            ICP = self.env['ir.config_parameter'].sudo()
            readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
            
            if readonly_mode == 'true':
                quota_info = ICP.get_param('storage.quota_info', 
                    'Storage quota exceeded. Contact administrator.')
                
                raise UserError(_(
                    "⛔ OPERATION BLOCKED\n\n"
                    "%s\n\n"
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    "READ-ONLY MODE ACTIVE\n"
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                    "You can:\n"
                    "✓ View records\n"
                    "✓ Search and filter\n"
                    "✓ Generate reports\n"
                    "✓ Delete records (to free space)\n\n"
                    "You CANNOT:\n"
                    "✗ Create new records\n"
                    "✗ Edit existing records\n"
                    "✗ Upload files\n\n"
                    "Contact your administrator to upgrade your storage plan."
                ) % quota_info)
            
        except UserError:
            # Re-raise UserError
            raise
        except Exception as e:
            # Log error but don't block operation
            _logger.warning("Storage quota check failed: %s", str(e))
            pass

    @api.model_create_multi
    def create(self, vals_list):
        """Block create if quota exceeded"""
        # Skip check for system models
        if self._name in ['ir.config_parameter', 'ir.logging', 'bus.bus']:
            return super().create(vals_list)
        
        self._check_storage_quota_before_write()
        return super().create(vals_list)

    def write(self, vals):
        """Block write if quota exceeded"""
        # Skip check for system models
        if self._name in ['ir.config_parameter', 'ir.logging', 'bus.bus']:
            return super().write(vals)
        
        self._check_storage_quota_before_write()
        return super().write(vals)

    def unlink(self):
        """Allow delete even in readonly (to free space)"""
        # Don't block delete - let users free up space
        return super().unlink()


class IrAttachmentStorageEnforcer(models.Model):
    """Block file uploads - Most important for storage"""
    _inherit = 'ir.attachment'

    @api.model_create_multi
    def create(self, vals_list):
        """Block file uploads if quota exceeded"""
        ICP = self.env['ir.config_parameter'].sudo()
        readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
        
        if readonly_mode == 'true':
            raise UserError(_(
                "⛔ FILE UPLOAD BLOCKED\n\n"
                "Your storage quota has been exceeded.\n"
                "Cannot upload new files or attachments.\n\n"
                "Please:\n"
                "1. Delete unnecessary files, OR\n"
                "2. Contact administrator to upgrade storage plan\n\n"
                "Current Status: READ-ONLY MODE"
            ))
        
        return super().create(vals_list)


class MailMessageStorageEnforcer(models.Model):
    """Block messages with attachments"""
    _inherit = 'mail.message'

    @api.model_create_multi
    def create(self, vals_list):
        """Block messages with attachments if quota exceeded"""
        ICP = self.env['ir.config_parameter'].sudo()
        readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
        
        if readonly_mode == 'true':
            # Check if any message has attachments
            for vals in vals_list:
                if vals.get('attachment_ids'):
                    raise UserError(_(
                        "⛔ CANNOT SEND MESSAGE WITH ATTACHMENTS\n\n"
                        "Storage quota exceeded.\n"
                        "You can send text messages only.\n\n"
                        "To send attachments, contact administrator to upgrade."
                    ))
        
        return super().create(vals_list)


class ResUsers(models.Model):
    """Show notification to users on login"""
    _inherit = 'res.users'

    @api.model
    def _check_credentials(self, password, user_agent_env):
        """Check and notify on login if readonly mode"""
        result = super()._check_credentials(password, user_agent_env)
        
        try:
            ICP = self.env['ir.config_parameter'].sudo()
            readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
            
            if readonly_mode == 'true':
                quota_info = ICP.get_param('storage.quota_info', '')
                _logger.warning(
                    "User %s logged in during READ-ONLY mode: %s",
                    self.login, quota_info
                )
        except Exception as e:
            _logger.error("Error checking readonly mode on login: %s", str(e))
        
        return result


# ==================== OPTIONAL: Show Banner via res.users ====================

class ResUsersInherit(models.Model):
    _inherit = 'res.users'
    
    @api.model
    def systray_get_activities(self):
        """Add storage warning to systray"""
        result = super().systray_get_activities()
        
        try:
            ICP = self.env['ir.config_parameter'].sudo()
            readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
            
            if readonly_mode == 'true':
                # Add warning to systray
                result.append({
                    'type': 'storage_warning',
                    'name': 'Storage Quota Exceeded',
                    'model': 'ir.config_parameter',
                    'icon': 'fa-exclamation-triangle',
                    'total_count': 1,
                    'actions': [{
                        'icon': 'fa-warning',
                        'name': 'READ-ONLY MODE: Storage quota exceeded'
                    }]
                })
        except Exception as e:
            _logger.error("Error adding storage warning to systray: %s", str(e))
        
        return result
