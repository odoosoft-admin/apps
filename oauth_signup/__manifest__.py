# -*- coding: utf-8 -*-
# Part of Odoosoft. See LICENSE file for full copyright and licensing details.

{
    'name': "OAuth Signup",

    'summary': """
        Allow users to sign up using Google, Facebook, LinkedIn and Twitter""",

    'description': """
Allow users to sign up using Google, Facebook, LinkedIn and Twitter
===================================================================
    """,

    'author': "Odoosoft",
    'website': "https://www.odoosoft.com",

    'category': 'Extra Tools',
    'version': '1.0',

    'depends': ['base', 'auth_oauth'],

    'data': [
        'security/ir.model.access.csv',
        'views/oauth_views.xml',
        'views/oauth_templates.xml',
        'data/data.xml',
    ],
    "external_dependencies": {
        'python': ['requests_oauthlib']
    },
}
