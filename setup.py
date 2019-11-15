from setuptools import setup, find_packages

setup(
	# Application name:
	name="msldap",

	# Version number (initial):
	version="0.2.4",

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/msldap",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Python library to play with MS LDAP",
	long_description="Python library to play with MS LDAP",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	install_requires=[
		'ldap3<2.5.2',
		'asn1crypto',
		'winsspi;platform_system=="Windows"',
		'socks5line>=0.0.3',
		'aiocmd',
		'asciitree',
	],
	entry_points={
		'console_scripts': [
			'msldap = msldap.examples.msldapclient:main',
		],
	}
)