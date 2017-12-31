# -*- coding: utf-8 -*-

from odoo import api, models, fields


class OauthProvider(models.Model):
    _name = 'oauth.oauth'
    _description = 'Oauth Provider'
    _order = 'sequence, id'

    name = fields.Char(string='Name', readonly=True, required=True)
    client_id = fields.Char(string='Client ID')
    client_secret = fields.Char(string='Client Secret')
    enabled = fields.Boolean(string='Allowed')
    sequence = fields.Integer()
    auth_endpoint = fields.Char(string='Authentication URL', required=True)
    oauth_type = fields.Selection([('oauth1', 'Oauth1'), ('oauth2', 'Oauth2')], required=True)

    # for Oauth1 only
    request_token_endpoint = fields.Char(string='Request Token URL')
    access_token_endpoint = fields.Char(string="Access Token_URL")

    # for Oauth2 only
    scope = fields.Char()

    after_login_url = fields.Char(string='Redirect URL', default='/', help="Redirect to this URL after successful sigup")
    icon = fields.Char('Icon', help="Icon font awesome class")
    help_url = fields.Char('Congiuration Help URL', readonly=True)
    help_callback = fields.Char(compute="get_help_callback", reload=True)

    @api.multi
    def get_help_callback(self):
        base_url = self.env['ir.config_parameter'].get_param('web.base.url')
        for provider in self:
            self.help_callback = '%s/%s/%s' % (base_url, provider.name.lower(), 'oauth-authorized')

    def get_provider(self, name):
        return self.search([('name', '=', name)])
