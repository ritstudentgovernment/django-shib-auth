import logging, re

from django.conf import settings
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured, PermissionDenied

from .app_settings import (
	SHIB_IDP_ATTRIB_NAME,
	SHIB_AUTHORIZED_IDPS,
	SHIB_ATTRIBUTE_MAP,
	SHIB_MOCK,
	SHIB_MOCK_ATTRIBUTES,
	SHIB_USERNAME_ATTRIB_NAME,
	SHIB_GROUP_ATTRIBUTES,
	SHIB_GROUPS_BY_IDP
)

logger = logging.getLogger(__name__)

class ShibbolethValidationError(Exception):
	pass

def ensure_auth_middleware(request):
	# AuthenticationMiddleware is required so that request.user exists.
	if not hasattr(request, 'user'):
		raise ImproperlyConfigured(
			"The Shib auth functions require the "
			"authentication middleware to be installed. Edit your "
			"MIDDLEWARE_CLASSES setting to insert"
			"'django.contrib.auth.middleware.AuthenticationMiddleware'."
		)

class ShibAuthCore:
	def logout(self, request):
		ensure_auth_middleware(request)

		auth.logout(request)
		request.session.flush() # Force the session to be discarded

	def login(self, request):
		ensure_auth_middleware(request)

		idp, username, shib_attrs = self._fetch_headers(request)

		new_user = auth.authenticate(request, username=username, shib_attrs=shib_attrs)

		if not new_user:
			# No one found... oops
			self.logout(request) # Log out anyone currently logged in to prevent session stealing
			raise PermissionDenied("User '{}' does not exist".format(username))

		# Check if a different user is already logged in to this session
		# If so, log them out of our session
		if not request.user.is_anonymous and request.user.username != new_user.username:
			self.logout(request)

		# User is valid.  Set request.user and persist user in the session
		# by logging the user in.
		if request.user.is_anonymous:
			auth.login(request, new_user)

		# We now have a valid user instance
		# Update its attributes with our shib meta to capture
		# any values that aren't on our model
		request.user.__dict__.update(shib_attrs)
		self._adjust_groups(request, request.user, idp)
		request.user.save()

	def _fetch_headers(self, request):
		# inject shib attributes
		if settings.DEBUG and SHIB_MOCK:
			logger.info('Overwriting shib headers with %s', SHIB_MOCK_ATTRIBUTES)
			request.META.update(SHIB_MOCK_ATTRIBUTES)

		idp = None
		if SHIB_IDP_ATTRIB_NAME is not None:
			idp = request.META.get(SHIB_IDP_ATTRIB_NAME, None)
			if not idp:
				raise ImproperlyConfigured("IdP header missing. Is this path protected by Shib?")

			if SHIB_AUTHORIZED_IDPS is not None and idp not in SHIB_AUTHORIZED_IDPS:
				logger.info("Unauthorized IdP: '%s'", idp)
				raise PermissionDenied("Unauthorized IdP: {}".format(idp))

		username = request.META.get(SHIB_USERNAME_ATTRIB_NAME, None)
		# If we got None or an empty value, something went wrong.
		if not username:
			raise ImproperlyConfigured(
				"Didn't get a shib username in the field called '{}'... "
				"Is this path protected by Shib?".format(SHIB_USERNAME_ATTRIB_NAME)
				)

		# Make sure we have all required Shibboleth elements before proceeding.
		shib_attrs, missing = self.parse_attributes(request)
		request.session['shib'] = shib_attrs

		if len(missing) != 0:
			raise ShibbolethValidationError(
				"All required Shibboleth elements not found. Missing: {}".format(missing)
			)

		return idp, username, shib_attrs

	def _adjust_groups(self, request, user, idp):
		ignored_groups = getattr(user, 'shib_ignored_groups', None)
		if ignored_groups:
			ignored_groups = ignored_groups.all().values_list('name', flat=True)
		else:
			ignored_groups = []

		groups = [
			group_name for group_name in self.parse_group_attributes(request, idp)
			if group_name not in ignored_groups
		]
		logger.info("These groups are ignored for user '%s': %s", user, ignored_groups)
		logger.info("Groups to adjust for '%s': %s", user, groups)

		# Remove the user from all groups that are not specified in the shibboleth metadata
		for group in user.groups.all():
			if group.name not in groups and group.name not in ignored_groups:
				logger.info("Removing user '%s' from group '%s'", user, group)
				group.user_set.remove(user)

		# Add the user to all groups in the shibboleth metadata
		for group_name in groups:
			group, created = auth.models.Group.objects.get_or_create(name=group_name)
			if created:
				logger.info("Creating new group '%s'", group)

			logger.info("Adding user '%s' to group '%s'", user, group)
			group.user_set.add(user)

	def parse_attributes(self, request):
		shib_attrs = {}
		missing = []

		meta = request.META
		for header, (required, name) in SHIB_ATTRIBUTE_MAP.items():
			value = shib_attrs[name] = meta.get(header, None)
			if required and not value:
				missing.append(name)

		return shib_attrs, missing

	def parse_group_attributes(self, request, idp):
		"""
		Parse the Shibboleth attributes for the SHIB_GROUP_ATTRIBUTES and generate a list of them.
		"""
		local_groups = ()

		if idp in SHIB_GROUPS_BY_IDP:
			local_groups = SHIB_GROUPS_BY_IDP[idp]

		remote_groups = set()
		for attr, attr_config in SHIB_GROUP_ATTRIBUTES.items():
			delimiter = attr_config.get('delimiter', ';')
			mappings = attr_config.get('mappings', None)
			whitelist = attr_config.get('whitelist', None)
			blacklist = attr_config.get('blacklist', None)

			parsed_groups = filter(None, re.split(delimiter, request.META.get(attr, '')))

			if whitelist:
				parsed_groups = filter(lambda g: g in whitelist, parsed_groups)
			elif blacklist:
				parsed_groups = filter(lambda g: g not in blacklist, parsed_groups)

			if mappings:
				parsed_groups = map(lambda g: mappings.get(g, g), parsed_groups)

			remote_groups = remote_groups.union(parsed_groups)

		logger.info("Groups configured for IdP '%s': locally: %s, remotely: %s",
			idp, local_groups, remote_groups
		)
		return remote_groups.union(local_groups)
