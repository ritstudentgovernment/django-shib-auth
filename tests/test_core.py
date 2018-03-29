from unittest import mock

from django import test
from django.test import TestCase
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, PermissionDenied

from django_shib_auth.core import(
	ShibAuthCore,
	ShibbolethValidationError
)

class EnsureAuthMiddlewareTestCase(TestCase):
	def setUp(self):
		self.core = ShibAuthCore()

	def test_throws_exception(self):
		self.assertRaises(ImproperlyConfigured, self.core.ensure_auth_middleware, None)
		self.assertRaises(ImproperlyConfigured, self.core.ensure_auth_middleware, object())

	def test_does_not_throw_exception(self):
		request = mock.MagicMock()
		request.user = True

		self.core.ensure_auth_middleware(request)

class LogoutTestCase(TestCase):
	@staticmethod
	def makeCore():
		core = ShibAuthCore(auth=mock.MagicMock())
		core.ensure_auth_middleware = mock.MagicMock()
		return core

	@staticmethod
	def makeRequest():
		request = mock.MagicMock()
		return request

	def test_raises_if_no_request_user(self):
		core = self.makeCore()
		request = mock.MagicMock(spec=[])

		self.assertRaises(ImproperlyConfigured, core.logout, request)

	def test_calls_auth_logout(self):
		core = self.makeCore()
		request = self.makeRequest()

		core.logout(request)
		core.auth.logout.assert_called_with(request)

	def test_calls_session_flush(self):
		core = self.makeCore()
		request = self.makeRequest()

		core.logout(request)
		request.session.flush.assert_called_with()

class LogInTestCase(TestCase):
	@staticmethod
	def makeUser(username='test', is_anon=False):
		user = mock.MagicMock()
		user.is_anonymous = is_anon
		user.username = username
		return user

	@staticmethod
	def makeCore(idp=None, username=None, shib_attrs=None, new_user='create'):
		if shib_attrs is None:
			shib_attrs = {}
		if new_user == 'create':
			new_user = LogInTestCase.makeUser(username=username)

		core = ShibAuthCore(auth=mock.MagicMock())
		core.auth.authenticate.return_value = new_user
		core.ensure_auth_middleware = mock.MagicMock()
		core._fetch_headers = mock.MagicMock(return_value=(idp, username, shib_attrs))
		core._adjust_groups = mock.MagicMock()
		return core

	@staticmethod
	def makeRequest(user='create'):
		if user == 'create':
			user = LogInTestCase.makeUser()

		request = mock.MagicMock()
		request.user = user
		return request

	def test_raises_if_no_request_user(self):
		core = self.makeCore()
		request = self.makeRequest()
		request.user = None

		self.assertRaises(ImproperlyConfigured, core.logout, request)

class ParseAttributesTestCase(TestCase):
	def test_extra(self):
		meta = {
			'uid': '123',
			'foo': 'bar'
		}
		request = mock.MagicMock()
		request.META = meta

		got, missing = ShibAuthCore(shib_attribute_map={
			'uid': (True, 'username'),
		}).parse_attributes(request)

		self.assertDictEqual(got, {
			'username': '123'
		})
		self.assertListEqual(missing, [])

	def test_missing_required(self):
		meta = {
			'uid': '123',
		}
		request = mock.MagicMock()
		request.META = meta

		got, missing = ShibAuthCore(shib_attribute_map={
			'uid': (True, 'username'),
			'required': (True, 'x')
		}).parse_attributes(request)

		self.assertDictEqual(got, {
			'username': '123'
		})
		self.assertListEqual(missing, ['required'])

	def test_missing_optional(self):
		meta = {
			'uid': '123',
		}
		request = mock.MagicMock()
		request.META = meta

		got, missing = ShibAuthCore(shib_attribute_map={
			'uid': (True, 'username'),
			'required': (False, 'x')
		}).parse_attributes(request)

		self.assertDictEqual(got, {
			'username': '123'
		})
		self.assertListEqual(missing, [])

	def test_missing_optional_implicit(self):
		meta = {
			'uid': '123',
		}
		request = mock.MagicMock()
		request.META = meta

		got, missing = ShibAuthCore(shib_attribute_map={
			'uid': (True, 'username'),
		}).parse_attributes(request)

		self.assertDictEqual(got, {
			'username': '123'
		})
		self.assertListEqual(missing, [])

