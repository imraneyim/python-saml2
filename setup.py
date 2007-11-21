#!/usr/bin/python
#
# Copyright (C) 2007 SIOS Technology, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from distutils.core import setup


setup(
    name='python-saml2',
    version='0.0.1',
    description='Python client library for SAML Version 2',
    long_description = """\
python-saml2 is a library for SAML Version 2.
""",
    author='Takashi Matsuo',
    author_email='matsuo.takashi@gmail.com',
    license='Apache 2.0',
    url='http://code.google.com/p/python-saml2/',
    packages=['saml2', 'xmldsig'],
    package_dir = {'saml2':'src/saml2', 'xmldsig':'src/xmldsig'}
)
