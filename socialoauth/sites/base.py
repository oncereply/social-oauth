# -*- coding: utf-8 -*-

import json
import urllib
from functools import wraps
from urllib import request
from urllib.parse import quote_plus

from socialoauth import SocialSites
from socialoauth.exception import SocialAPIError, SocialSitesConfigError

HTTP_TIMEOUT = 10

socialsites = SocialSites()
if not socialsites.configed:
    raise SocialSitesConfigError("SocialSites not configed yet, Do it first!")


def _http_error_handler(func):
    @wraps(func)
    def deco(self, *args, **kwargs):
        try:
            res = func(self, *args, **kwargs)
        except request.HTTPError as e:
            raise SocialAPIError(self.site_name, e.url, e.read())
        except request.URLError as e:
            raise SocialAPIError(self.site_name, args[0], e.reason)

        error_key = getattr(self, 'RESPONSE_ERROR_KEY', None)
        if error_key is not None and error_key in res:
            raise SocialAPIError(self.site_name, args[0], res)

        return res

    return deco


def _encode_params(**kw):
    """
    Encode parameters.
    """
    args = []
    for k, v in kw.items():
        qv = v.encode('utf-8') if isinstance(v, str) else str(v)
        args.append('%s=%s' % (k, urllib.parse.quote(qv)))
    return '&'.join(args)


class JsonObject(dict):
    """
    general json object that can bind any fields but also act as a dict.
    """

    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value


def _obj_hook(pairs):
    """
    convert json object to python object.
    """
    o = JsonObject()
    for k, v in pairs.items():
        o[str(k)] = v
    return o


class OAuth2(object):
    """Base OAuth2 class, Sub class must define the following settings:

    AUTHORIZE_URL    - Asking user to authorize and get token
    ACCESS_TOKEN_URL - Get authorized access token

    And the bellowing should define in settings file

    REDIRECT_URI     - The url after user authorized and redirect to
    CLIENT_ID        - Your client id for the social site
    CLIENT_SECRET    - Your client secret for the social site

    Also, If the Website needs scope parameters, your should add it too.

    SCOPE            - A list type contains some scopes

    Details see: http://tools.ietf.org/html/rfc6749


    SubClass MUST Implement the following three methods:

    build_api_url(self, url)
    build_api_data(self, **kwargs)
    parse_token_response(self, res)
    """
    AUTHORIZE_URL = 'https://api.weibo.com/oauth2/authorize'
    ACCESS_TOKEN_URL = 'https://api.weibo.com/oauth2/access_token'
    CLIENT_SECRET = None
    SCOPE = None
    REDIRECT_URI = None
    CLIENT_ID = None

    def __init__(self):
        """Get config from settings.
        class instance will have the following properties:
        
        site_name
        site_id
        REDIRECT_URI
        CLIENT_ID
        CLIENT_SECRET
        """
        key = '%s.%s' % (self.__class__.__module__, self.__class__.__name__)
        configs = socialsites.load_config(key)
        for k, v in configs.items():
            setattr(self, k, v)

    @_http_error_handler
    def http_get(self, url, data, parse=True):
        params = _encode_params(**data)
        http_url = '%s?%s' % (url, params)
        req = request.Request('%s?%s' % (http_url, None))
        self.http_add_header(req)
        res = request.urlopen(req, timeout=HTTP_TIMEOUT)
        body = res.read().decode("utf-8")
        if parse:
            return json.loads(body, object_hook=_obj_hook)
        return res

    @_http_error_handler
    def http_post(self, url, data, parse=True):
        params = _encode_params(**data)
        req = request.Request(url, data=params.encode(encoding='utf-8'))
        self.http_add_header(req)
        res = request.urlopen(req, timeout=HTTP_TIMEOUT)
        body = res.read().decode("utf-8")
        if parse:
            return json.loads(body, object_hook=_obj_hook)
        return res

    def http_add_header(self, req):
        """Sub class rewiter this function If it's necessary to add headers"""
        pass

    @property
    def authorize_url(self, redirect_uri=None):
        """Rewrite this property method If there are more arguments
        need  attach to the url. Like bellow:

            class NewSubClass(OAuth2):
                @property
                def authorize_url(self):
                    url = super(NewSubClass, self).authorize_url
                    url += '&blabla'
                    return url
        """
        redirect_uri = self.REDIRECT_URI if redirect_uri is None else redirect_uri
        url = "%s?client_id=%s&response_type=code&redirect_uri=%s" % (
            self.AUTHORIZE_URL, self.CLIENT_ID, quote_plus(redirect_uri)
        )

        if getattr(self, 'SCOPE', None) is not None:
            url = '%s&scope=%s' % (url, '+'.join(self.SCOPE))

        return url

    def get_access_token(self, code, method='POST', parse=True):
        """parse is True means that the api return a json string. 
        So, the result will be parsed by json library.
        Most sites will follow this rule, return a json string.
        But some sites (e.g. Tencent), Will return an non json string,
        This sites MUST set parse=False when call this method,
        And handle the result by themselves.

        This method Maybe raise SocialAPIError.
        Application MUST try this Exception.
        """

        data = {
            'client_id': self.CLIENT_ID,
            'client_secret': self.CLIENT_SECRET,
            'redirect_uri': self.REDIRECT_URI,
            'code': code,
            'grant_type': 'authorization_code'
        }

        if method == 'POST':
            res = self.http_post(self.ACCESS_TOKEN_URL, data, parse=parse)
        else:
            res = self.http_get(self.ACCESS_TOKEN_URL, data, parse=parse)

        self.parse_token_response(res)

    def api_call_get(self, url=None, **kwargs):
        url = self.build_api_url(url)
        data = self.build_api_data(**kwargs)
        return self.http_get(url, data)

    def api_call_post(self, url=None, **kwargs):
        url = self.build_api_url(url)
        data = self.build_api_data(**kwargs)
        return self.http_post(url, data)

    def parse_token_response(self, res):
        """
        Subclass MUST implement this method
        And set the following attributes:

        access_token,
        uid,
        name,
        avatar,
        """
        raise NotImplementedError()

    def build_api_url(self, url):
        raise NotImplementedError()

    def build_api_data(self, **kwargs):
        raise NotImplementedError()
