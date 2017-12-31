# -*- coding: utf-8 -*-
from odoo import api, http, SUPERUSER_ID
from odoo.http import request
from odoo import registry as registry_get
from odoo.addons.web.controllers.main import login_and_redirect
from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home

import base64
import logging
import requests

_logger = logging.getLogger(__name__)

try:
    from requests_oauthlib import OAuth1Session, OAuth2Session
    from requests_oauthlib.compliance_fixes import linkedin_compliance_fix, facebook_compliance_fix
except ImportError:
    _logger.warning('requests_oauthlib library not found, please install the requests_oauthlib library from https://pypi.python.org/pypi/requests-oauthlib')


class SocialProvider(Home):
    @http.route()
    def web_login(self, *args, **kw):
        response = super(SocialProvider, self).web_login(*args, **kw)
        providers = request.env['oauth.oauth'].sudo().search([])
        provider_list = []
        for provider in providers:
            if provider.enabled and provider.client_id and provider.client_secret:
                name = provider.name
                provider_list.append({
                    'name': name,
                    'link': '/oauth/%s/' % name.lower(),
                    'icon': provider.icon
                })
        response.qcontext['oauth_providers'] = provider_list
        return response


class Oauth(http.Controller):

    def get_callback_url(self, name):
        base_url = request.env['ir.config_parameter'].sudo().get_param('web.base.url')
        return '%s/%s/%s' % (base_url, name, 'oauth-authorized')

    def fetch_image(self, url):
        if not url:
            return False
        response = requests.get(url)
        image_base64 = False
        if 'image/' in response.headers['Content-Type']:
            image_base64 = base64.b64encode(response.content)
        return image_base64
    # =========
    #  Twitter
    # =========
    @http.route('/oauth/twitter/', auth='public')
    def twitter_oauth(self, **kw):
        Oauth = request.env['oauth.oauth']
        twitter = Oauth.sudo().get_provider('Twitter')
        callback_uri = self.get_callback_url('twitter')
        oauth = OAuth1Session(twitter.client_id, client_secret=twitter.client_secret, callback_uri=callback_uri)
        fetch_response = oauth.fetch_request_token(twitter.request_token_endpoint)
        resource_owner_key = fetch_response.get('oauth_token')
        resource_owner_secret = fetch_response.get('oauth_token_secret')
        request.session['twitter_tokens'] = (resource_owner_key, resource_owner_secret)
        authorization_url = oauth.authorization_url(twitter.auth_endpoint)
        return http.redirect_with_hash(authorization_url)

    @http.route('/twitter/oauth-authorized', auth='public')
    def twitter_authorized(self, oauth_verifier, **kw):
        Oauth = request.env['oauth.oauth']
        twitter = Oauth.sudo().get_provider('Twitter')
        resource_owner_key, resource_owner_secret = request.session['twitter_tokens']
        oauth_test = OAuth1Session(twitter.client_id,
                          client_secret=twitter.client_secret,
                          resource_owner_key=resource_owner_key,
                          resource_owner_secret=resource_owner_secret,
                          verifier=oauth_verifier)
        oauth_tokens = oauth_test.fetch_access_token(twitter.access_token_endpoint)
        access_token = oauth_tokens['oauth_token']

        url = 'https://twitter.com/%s/profile_image?size=original' % oauth_tokens['screen_name']
        image = self.fetch_image(url)
        vals = {
            'oauth_access_token': access_token,
            'name': oauth_tokens['screen_name'],
            'oauth_uid': oauth_tokens['user_id'],
            'image': image
        }
        provider_id = twitter.id
        db = request.session['db']
        registry = registry_get(db)
        after_login_url = twitter.after_login_url
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            try:
                login = env['res.users'].sudo()._singup_user(provider_id, vals)
            except Exception as e:
                return request.render('web.login', {'error': e.message})
            cr.commit()
            request._cr.commit()
            res = login_and_redirect(db, login, access_token, after_login_url)
            return res

    # =========
    #  Facebook
    # =========
    @http.route('/oauth/facebook/', auth='public')
    def facebook_oauth(self, **kw):
        Oauth = request.env['oauth.oauth']
        facebook = Oauth.sudo().get_provider('Facebook')
        callback_uri = self.get_callback_url('facebook')
        scope = [
            "email"
        ]
        oauth_session = OAuth2Session(facebook.client_id, scope=scope, redirect_uri=callback_uri)
        oauth_session = facebook_compliance_fix(oauth_session)
        authorization_url, state = oauth_session.authorization_url(facebook.auth_endpoint)
        return http.redirect_with_hash(authorization_url)

    @http.route('/facebook/oauth-authorized', auth='public')
    def facebook_authorized(self, state, code, **kw):
        Oauth = request.env['oauth.oauth']
        facebook = Oauth.sudo().get_provider('Facebook')
        callback_uri = self.get_callback_url('facebook')
        oauth_session = OAuth2Session(facebook.client_id, redirect_uri=callback_uri)
        oauth_session.fetch_token(facebook.access_token_endpoint, code=code, client_secret=facebook.client_secret)
        user_response = oauth_session.get('https://graph.facebook.com/me?fields=id,name,email')
        user_info = user_response.json()
        url = 'https://graph.facebook.com/%s/picture?type=large' % user_info['id']
        image = self.fetch_image(url)
        access_token = user_info['id']

        vals = {
            'oauth_access_token': access_token,
            'name': user_info['name'],
            'oauth_uid': user_info['id'],
            'email': user_info['email'],
            'image': image
        }
        provider_id = facebook.id
        db = request.session['db']
        registry = registry_get(db)
        after_login_url = facebook.after_login_url
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            try:
                login = env['res.users'].sudo()._singup_user(provider_id, vals)
            except Exception as e:
                return request.render('web.login', {'error': e.message})
            cr.commit()
            request._cr.commit()
            res = login_and_redirect(db, login, access_token, after_login_url)
            return res

    # =========
    #  Google
    # =========
    @http.route('/oauth/google/', auth='public')
    def google_oauth(self, **kw):
        Oauth = request.env['oauth.oauth']
        google = Oauth.sudo().get_provider('Google')
        callback_uri = self.get_callback_url('google')
        scope = [
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
        oauth = OAuth2Session(google.client_id, scope=scope, redirect_uri=callback_uri)
        authorization_url, state = oauth.authorization_url(google.auth_endpoint)
        return http.redirect_with_hash(authorization_url)

    @http.route('/google/oauth-authorized', auth='public')
    def google_authorized(self, state, code, **kw):
        Oauth = request.env['oauth.oauth']
        google = Oauth.sudo().get_provider('Google')
        callback_uri = self.get_callback_url('google')
        oauth_session = OAuth2Session(google.client_id, redirect_uri=callback_uri)
        oauth_session.fetch_token(google.access_token_endpoint, code=code, client_secret=google.client_secret)
        user_response = oauth_session.get('https://www.googleapis.com/oauth2/v1/userinfo')
        user_info = user_response.json()
        # need to be pass refresh token but user id will be ok !
        access_token = user_info['id']
        url = user_info['picture']
        image = self.fetch_image(url)
        vals = {
            'oauth_access_token': access_token,
            'name': user_info['name'],
            'oauth_uid': user_info['id'],
            'email': user_info['email'],
            'image': image,
        }
        provider_id = google.id
        db = request.session['db']
        registry = registry_get(db)
        after_login_url = google.after_login_url
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            try:
                login = env['res.users'].sudo()._singup_user(provider_id, vals)
            except Exception as e:
                return request.render('web.login', {'error': e.message})
            cr.commit()
            request._cr.commit()
            return login_and_redirect(db, login, access_token, after_login_url)

    # =========
    #  Linkedin
    # =========
    @http.route('/oauth/linkedin/', type='http', auth='none')
    def linkedin_oauth(self, **kw):
        Oauth = request.env['oauth.oauth']
        linkedin = Oauth.sudo().get_provider('Linkedin')
        callback_uri = self.get_callback_url('linkedin')
        oauth_session = OAuth2Session(linkedin.client_id, redirect_uri=callback_uri)
        oauth_session = linkedin_compliance_fix(oauth_session)
        authorization_url, state = oauth_session.authorization_url(linkedin.auth_endpoint)
        return http.redirect_with_hash(authorization_url)

    @http.route('/linkedin/oauth-authorized', type='http', auth='none')
    def linkedin_authorized(self, code, **kw):
        Oauth = request.env['oauth.oauth']
        linkedin = Oauth.sudo().get_provider('Linkedin')
        callback_uri = self.get_callback_url('linkedin')
        oauth_session = OAuth2Session(linkedin.client_id, redirect_uri=callback_uri)
        oauth_session.fetch_token(linkedin.access_token_endpoint, code=code, client_secret=linkedin.client_secret)
        user_response = oauth_session.get('https://api.linkedin.com/v1/people/~:(id,email-address,first-name,last-name,picture-urls::(original))?format=json')
        user_info = user_response.json()
        url = user_info.get('pictureUrls', {}).get('values', [False])[0]
        image = self.fetch_image(url)
        name = user_info['firstName'] + ' ' + user_info['lastName']
        email = user_info['emailAddress']
        oauth_uid = access_token = user_info['id']
        vals = {
            'oauth_access_token': access_token,
            'name': name,
            'oauth_uid': oauth_uid,
            'email': email,
            'image': image,
        }
        provider_id = linkedin.id
        db = request.session['db']
        registry = registry_get(db)
        after_login_url = linkedin.after_login_url
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            try:
                login = env['res.users'].sudo()._singup_user(provider_id, vals)
            except Exception as e:
                return request.render('web.login', {'error': e.message})
            cr.commit()
            request._cr.commit()
            res = login_and_redirect(db, login, access_token, after_login_url)
            return res
