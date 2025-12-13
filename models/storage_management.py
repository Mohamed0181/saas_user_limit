# models/storage_quota_enforcer.py
# هذا الموديل ينزل مع كل عميل ويمنعه من الكتابة

from odoo import models, api, _
from odoo.exceptions import AccessError
import logging

_logger = logging.getLogger(__name__)


class BaseModelStorageEnforcer(models.AbstractModel):
    """
    هذا الموديل يتم inherit في كل Models
    ويمنع العميل من Create/Write/Unlink لو المساحة ممتلئة
    """
    _inherit = 'base'

    def _check_storage_quota(self):
        """Check if storage quota is exceeded"""
        try:
            # Get readonly mode from system parameters
            ICP = self.env['ir.config_parameter'].sudo()
            readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
            
            if readonly_mode == 'true':
                # Get quota info
                quota_info = ICP.get_param('storage.quota_info', '')
                
                raise AccessError(_(
                    "⛔ STORAGE QUOTA EXCEEDED - READ-ONLY MODE\n\n"
                    "%s\n\n"
                    "You cannot create, edit or delete records.\n"
                    "Please contact your administrator to upgrade your storage plan."
                ) % (quota_info or "Your storage quota has been exceeded"))
            
            return True
            
        except AccessError:
            raise
        except Exception as e:
            # If check fails, allow operation (don't block normal operations)
            _logger.warning("Storage quota check failed: %s", str(e))
            return True

    @api.model_create_multi
    def create(self, vals_list):
        """Override create to check storage quota"""
        # Check quota before creating
        self._check_storage_quota()
        return super(BaseModelStorageEnforcer, self).create(vals_list)

    def write(self, vals):
        """Override write to check storage quota"""
        # Check quota before writing
        self._check_storage_quota()
        return super(BaseModelStorageEnforcer, self).write(vals)

    def unlink(self):
        """Override unlink to check storage quota"""
        # Allow delete even in readonly mode (to free up space)
        # If you want to block delete too, uncomment below:
        # self._check_storage_quota()
        return super(BaseModelStorageEnforcer, self).unlink()


class IrAttachmentStorageEnforcer(models.Model):
    """
    خاص بـ الملفات - منع رفع الملفات لو المساحة ممتلئة
    """
    _inherit = 'ir.attachment'

    @api.model_create_multi
    def create(self, vals_list):
        """Block file uploads if quota exceeded"""
        ICP = self.env['ir.config_parameter'].sudo()
        readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
        
        if readonly_mode == 'true':
            raise AccessError(_(
                "⛔ FILE UPLOAD BLOCKED\n\n"
                "Your storage quota has been exceeded.\n"
                "Cannot upload new files.\n\n"
                "Please contact your administrator to upgrade your storage plan."
            ))
        
        return super(IrAttachmentStorageEnforcer, self).create(vals_list)


class MailMessageStorageEnforcer(models.Model):
    """
    منع إرسال رسائل مع مرفقات لو المساحة ممتلئة
    """
    _inherit = 'mail.message'

    @api.model_create_multi
    def create(self, vals_list):
        """Block messages with attachments if quota exceeded"""
        ICP = self.env['ir.config_parameter'].sudo()
        readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
        
        if readonly_mode == 'true':
            # Check if message has attachments
            for vals in vals_list:
                if vals.get('attachment_ids'):
                    raise AccessError(_(
                        "⛔ CANNOT SEND MESSAGE WITH ATTACHMENTS\n\n"
                        "Your storage quota has been exceeded.\n"
                        "You can send messages without attachments only.\n\n"
                        "Please contact your administrator to upgrade your storage plan."
                    ))
        
        return super(MailMessageStorageEnforcer, self).create(vals_list)


# ==================== Storage Banner Widget ====================

class StorageQuotaBanner(models.TransientModel):
    """
    موديل لعرض Banner التحذير
    """
    _name = 'storage.quota.banner'
    _description = 'Storage Quota Warning Banner'

    @api.model
    def get_banner_info(self):
        """Get storage quota banner information"""
        ICP = self.env['ir.config_parameter'].sudo()
        readonly_mode = ICP.get_param('storage.readonly_mode', 'false')
        
        if readonly_mode == 'true':
            quota_info = ICP.get_param('storage.quota_info', '')
            
            return {
                'show_banner': True,
                'message': quota_info or 'Storage quota exceeded - READ-ONLY MODE',
                'type': 'danger'
            }
        
        # Check warning level
        quota_percentage = float(ICP.get_param('storage.quota_percentage', '0'))
        
        if quota_percentage >= 90:
            return {
                'show_banner': True,
                'message': f'⚠️ Storage warning: {quota_percentage:.1f}% used',
                'type': 'warning'
            }
        
        return {
            'show_banner': False,
            'message': '',
            'type': 'info'
        }
