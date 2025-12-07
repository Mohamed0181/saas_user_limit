# -*- coding: utf-8 -*-
{
    'name': 'Odoo Management',
    'category': 'Odoo Management',
    'summary': 'Control odoo',
    'author': 'Optimum Smart Solutions',
    'license': 'LGPL-3',
    'depends': ['base'],
    'data': [
        'security/ir.model.access.csv',
        'data/user_limit_data.xml',
    ],
    'auto_install': False,  # تم تغيير التثبيت يدوى مؤقت لحين الانتهاء اً
    'installable': True,
    'application': False,
}