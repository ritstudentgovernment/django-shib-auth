from django.contrib.auth import get_user_model
from django.contrib.auth.backends import RemoteUserBackend

UserModel = get_user_model()
MODEL_FIELD_NAMES = [x.name for x in UserModel._meta.get_fields()]

class ShibbolethBackend(RemoteUserBackend):
	"""
	An authentication backend that reads Shibboleth data to authenticate
	"""
	def __init__(self, create_unknown_user=True):
		# Create a User object if not already in the database?
		self.create_unknown_user = create_unknown_user

	def authenticate(self, request=None, username=None, shib_attrs=None): #pylint: disable=arguments-differ
		if not request or not username or not shib_attrs:
			return None # This request is not meant for us

		username = self.clean_username(username)

		if self.create_unknown_user:
			# Only pull out the model attributes to pass to create
			model_field_dict = dict(
				((key, value) for key, value in shib_attrs.items() if key in MODEL_FIELD_NAMES)
			)

			user, created = UserModel.objects.get_or_create(**{
				UserModel.USERNAME_FIELD: username
			}, defaults=model_field_dict)
			if created:
				user = self.configure_user(user, shib_attrs=shib_attrs)
		else:
			try:
				user = UserModel._default_manager.get_by_natural_key(username) #pylint: disable=protected-access
			except UserModel.DoesNotExist:
				return None # Bail out if we can't find the user
		#endif

		return user if self.user_can_authenticate(user) else None

	def configure_user(self, user, shib_attrs): #pylint: disable=arguments-differ,unused-argument
		user.set_unusable_password()
		user.save()
		return user
