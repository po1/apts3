#!/usr/bin/env python

from distutils.core import setup

setup(name='apts3',
      version='0.1',
      description='Manage a simple APT repo on hosted on S3',
      author='Paul Mathieu',
      author_email='paul@ponteilla.net',
      url='https://github.com/po1/apts3',
      packages=['apts3'],
      install_requires=[
          'boto3',
#          'apt',  # how do we specify this?
          ],
      entry_points={
          'console_scripts': ['apts3=apts3.lib:main'],
          },
     )
