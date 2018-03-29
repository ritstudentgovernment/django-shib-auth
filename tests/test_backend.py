from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django_shib_auth.backends import ShibbolethBackend

class BackendTestCase(TestCase):
	def setUp(self):
		self.bob = User.objects.create_user('bob')
		self.steve_attrs = {
			'email': 'steve@example.com',
			'first_name': 'steve'
		}
		self.steve = User.objects.create_user('steve', **self.steve_attrs)
		self.backend = ShibbolethBackend(False)
		self.creating_backend = ShibbolethBackend(True)

	def test_authenticate_missing_params(self):
		self.assertIsNone(self.backend.authenticate())
		self.assertIsNone(self.backend.authenticate(username='foo'))

	def test_authenticate_existing_user(self):
		user = self.backend.authenticate(self, 'bob', {})
		self.assertEqual(user, self.bob)
	
	def test_authenticate_existing_user_with_same_attrs(self):
		user = self.backend.authenticate(self, 'steve', self.steve_attrs)
		self.assertEqual(user, self.steve)
		self.assertDictContainsSubset(self.steve_attrs, user.__dict__)		
		
	def test_authenticate_existing_user_with_different_attrs(self):
		user = self.backend.authenticate(self, 'steve', {
			'email': 'foo@bar.com',
			'first_name': 'joe'
		})
		self.assertEqual(user, self.steve)

		self.assertDictContainsSubset(self.steve_attrs, user.__dict__)

	def test_authenticate_missing_user(self):
		self.assertIsNone(self.backend.authenticate(self, 'missing', {}))
	
	def test_create_missing_user(self):
		user = self.creating_backend.authenticate(self, 'test', {})
		self.assertIsNotNone(user)
		user.delete()

	def test_create_missing_user_with_attrs(self):
		user = self.creating_backend.authenticate(self, 'test', {
			'email': 'foo@bar.com'
		})
		self.assertIsNotNone(user)
		self.assertEqual(user.email, 'foo@bar.com')
		user.delete()

	def test_create_missing_user_with_extra_attrs(self):
		user = self.creating_backend.authenticate(self, 'test', {
			'email': 'foo@bar.com',
			'extra': 'qwerty'
		})
		
		self.assertIsNotNone(user)
		self.assertEqual(user.email, 'foo@bar.com')
		self.assertFalse(hasattr(user, 'extra'))

		user.delete()

	def test_creating_user_calls_configure_user(self):
		backend = ShibbolethBackend(True)
		backend.configure_user = mock.MagicMock()

		user = backend.authenticate(self, 'idontexist', {})

		self.assertTrue(backend.configure_user.called)
		
		user.delete()

	def test_getting_user_does_not_call_configure_user(self):
		backend = ShibbolethBackend(True)
		backend.configure_user = mock.MagicMock()

		user = backend.authenticate(self, 'bob', {})

		backend.configure_user.assert_not_called()

		backend = ShibbolethBackend(False)
		backend.configure_user = mock.MagicMock()

		user = backend.authenticate(self, 'bob', {})

		backend.configure_user.assert_not_called()
