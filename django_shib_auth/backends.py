from django.contrib.auth import get_user_model
from django.contrib.auth.backends import RemoteUserBackend


class ShibbolethBackend(RemoteUserBackend):
	"""
	An authentication backend that reads Shibboleth data to authenticate
	"""
	def __init__(self, create_unknown_user=True, user_model=get_user_model()):
		# Create a User object if not already in the database?
		self.create_unknown_user = create_unknown_user
		self.user_model = user_model
		self.model_field_names = [x.name for x in user_model._meta.get_fields()]

	def authenticate(self, request=None, username=None, shib_attrs=None): #pylint: disable=arguments-differ
		if None in (request, username, shib_attrs):
			return None # This request is not meant for us

		username = self.clean_username(username)

		if self.create_unknown_user:
			# Only pull out the model attributes to pass to create
			model_field_dict = dict(
				((key, value) for key, value in shib_attrs.items() if key in self.model_field_names)
			)

			user, created = self.user_model.objects.get_or_create(**{
				self.user_model.USERNAME_FIELD: username
			}, defaults=model_field_dict)
			if created:
				user = self.configure_user(user, shib_attrs=shib_attrs)
		else:
			try:
				user = self.user_model._default_manager.get_by_natural_key(username) #pylint: disable=protected-access
			except self.user_model.DoesNotExist:
				return None # Bail out if we can't find the user
		#endif

		return user if self.user_can_authenticate(user) else None

	def configure_user(self, user, shib_attrs): #pylint: disable=arguments-differ,unused-argument
		user.set_unusable_password()
		user.save()
		return user
