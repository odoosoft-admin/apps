# -*- coding: utf-8 -*-

from odoo import api, fields, models
from odoo.exceptions import AccessDenied


class ResUsers(models.Model):
    _inherit = 'res.users'

    oauth_provider_id = fields.Many2one('oauth.oauth', string='OAuth Provider')

    @api.model
    def _create_sinup_detail(self, provider, vals):
        oauth_uid = vals['oauth_uid']
        login = vals.get('email') or vals.get('name')  # for twitter name is login and google explicit pass by contorller
        email = vals.get('email', '%s_user_%s' % (provider.name, oauth_uid))
        name = vals.get('name', email)
        return dict(vals,
                    name=name,
                    login=login,
                    email=email,
                    oauth_provider_id=provider.id,
                    active=True
                    )

    @api.model
    def _singup_user(self, provider_id, vals):
        provider = self.env['oauth.oauth'].sudo().browse(provider_id)
        user_detail = self._create_sinup_detail(provider, vals)
        login = self._auth_oauth_user(provider, user_detail)
        return login

    @api.model
    def _auth_oauth_user(self, provider, user_detail):
        oauth_uid = user_detail['oauth_uid']
        try:
            oauth_user = self.search([("oauth_uid", "=", oauth_uid), ('oauth_provider_id', '=', provider.id)])
            if not oauth_user:
                raise AccessDenied()
            assert len(oauth_user) == 1
            oauth_user.write({'oauth_access_token': user_detail['oauth_access_token']})
            return oauth_user.login
        except AccessDenied:
            if self.env.context.get('no_user_creation'):
                return None
            _, login, _ = self.signup(user_detail)
            return login
            
