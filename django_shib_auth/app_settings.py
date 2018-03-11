from django.conf import settings

SHIB_IDP_ATTRIB_NAME = getattr(settings, 'SHIB_IDP_ATTRIB_NAME')
SHIB_AUTHORIZED_IDPS = getattr(settings, 'SHIB_AUTHORIZED_IDPS')


# Name of the shib header that contains the username
SHIB_USERNAME_ATTRIB_NAME = getattr(settings, 'SHIB_USERNAME_ATTRIB_NAME', 'uid')

# Dictionary of `SHIB_ATTRIB_NAME: (required, python_name)`
# At a minimum you will need username
SHIB_ATTRIBUTE_MAP = getattr(settings, 'SHIB_ATTRIBUTE_MAP', {
	SHIB_USERNAME_ATTRIB_NAME: (True, "username")
})

# Test mode injects the specified shib attributes
# Set to true if you are testing and want to insert sample headers.
# ONLY WORKS IN DEBUG MODE
SHIB_MOCK = getattr(settings, 'SHIB_MOCK', False)

# A dictionary of `SHIB_HEADER: VALUE` to inject
SHIB_MOCK_ATTRIBUTES = getattr(settings, 'SHIB_MOCK_ATTRIBUTES')

# This list of attributes will map to Django permission groups
SHIB_GROUP_ATTRIBUTES = getattr(settings, 'SHIB_GROUP_ATTRIBUTES', {})
# sample_groups = {
# 	'AFFILIATION': { # Name of the SHIB attribute that contains group information
# 		'delimiter': ',', # Regex to split group names by. Defaults to ';'
# 		'mappings': { # Mappings of `SHIB_GROUP_NAME: Django Group`
# 			'STUDENT': 'Student',
# 			'STAFF': 'Maintenance'
# 		}
# 	}
# }

# Groups that should always be added to a user when they come from a specific IdP
SHIB_GROUPS_BY_IDP = getattr(settings, 'SHIB_GROUPS_BY_IDP', {})
