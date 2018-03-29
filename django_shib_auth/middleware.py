import logging

from django.contrib.auth.middleware import RemoteUserMiddleware
from django.core.exceptions import PermissionDenied

from .core import ShibSessionAuthCore

logger = logging.getLogger(__name__)

class ShibbolethRemoteUserMiddleware(ShibSessionAuthCore, RemoteUserMiddleware):
	"""
	Authentication Middleware for use with Shibboleth.
	Will attempt to authenticate the user on EVERY request
	"""
	def process_request(self, request):
		try:
			self.login(request)
		except PermissionDenied:
			logger.exception('Failed to log user in via Shib')
