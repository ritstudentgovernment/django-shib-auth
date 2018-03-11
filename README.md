# django-shib-auth

A Django plugin to support multiple schemes for authenticating via Shibboleth. Loosely based on [django-shibboleth-remoteuser](https://github.com/Brown-University-Library/django-shibboleth-remoteuser) and [shibboleth_session_auth](https://github.com/esnet/shibboleth_session_auth).

This plugin will obtain user information from Shibboleth attributes and bridge it over to Django's auth system. Users will be created/updated as needed, and group membership can be modified based on Shibboleth's `AFFILIATION` attributes.

This plugin aims to do the hard work of interfacing with Shibboleth and let your essentially drop it in and continue using Django's Auth system as normal.

## Basic Setup
1. Install this package
2. Add `django_shib_auth.backends.ShibbolethBackend` or a derived class to your `AUTHENTICATION_BACKENDS` setting
3. Configure settings for `django-shib-auth`
4. Set up either URL-Based Login or Whole-Surface login

### URL-Based Login
This is the recommended way to configure Shibboleth authentication. In this setup, Shibboleth is configured to protect a single path, eg `/myapp/login/`. Django-shib-auth is then used to listen at that URL. Once a user successfully authenticates with Shibboleth, the request is passed to Django-shib-auth, which bridges the Shibboleth data to Django's auth system and logs the user in. From this point on, **Django** maintains the session and can control things such as longevity.

To enable:
1. Add entries to your UrlConf for `django_shib_auth.views.LoginView` and `django_shib_auth.views.LogoutView`
2. You may wish to update your `LOGIN_URL` setting

### Whole-Surface Login
This is an alternate login scheme. In Whole-Surface login, **every** request is protected by Shibboleth. This is good for sites that don't have a single unified "login" view, but it incurs a penalty from Shibboleth overhead on every request. Also, since Shibboleth is actively involved in every request, the session lifetime is effectively limited by Shibboleth's configuration.

To enable:
1. Add `django_shib_auth.middleware.ShibbolethRemoteUserMiddleware` to your `MIDDLEWARES` after Django's `AuthenticationMiddleware`

## Settings

TODO but there are lots