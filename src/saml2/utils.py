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

"""Contains utility methods used with SAML-2."""

__author__ = 'tmatsuo@sios.com (Takashi MATSUO)'

"""Contains utility methods for SAML-2.
"""

import xmldsig as ds
from saml2 import saml, samlp
import StringIO
import libxml2
import xmlsec

# TODO: write unittests for these methods

def createID():
  ret = ""
  for i in range(40):
    ret = ret + chr(random.randint(0, 15) + ord('a'));
  return ret

def getDateAndTime(slice=0):
  return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + slice))

def lib_init():
  # Init libxml library
  libxml2.initParser()
  libxml2.substituteEntitiesDefault(1)

  # Init xmlsec library
  if xmlsec.init() < 0:
    raise(saml2.Error("Error: xmlsec initialization failed."))

  # Check loaded library version
  if xmlsec.checkVersion() != 1:
    raise(saml2.Error(
      "Error: loaded xmlsec library version is not compatible.\n"))

  # Init crypto library
  if xmlsec.cryptoAppInit(None) < 0:
    raise(saml2.Error("Error: crypto initialization failed."))

  # Init xmlsec-crypto library
  if xmlsec.cryptoInit() < 0:
    raise(saml2.Error("Error: xmlsec-crypto initialization failed."))  

def lib_shutdown():
  # Shutdown xmlsec-crypto library
  xmlsec.cryptoShutdown()

  # Shutdown crypto library
  xmlsec.cryptoAppShutdown()

  # Shutdown xmlsec library
  xmlsec.shutdown()

  # Shutdown LibXML2
  libxml2.cleanupParser()

def verify(xml, key_file):
  lib_init()
  ret = verify_xml(xml, key_file)
  lib_shutdown()
  return ret == 0

# Verifies XML signature in xml_file using public key from key_file.
# Returns 0 on success or a negative value if an error occurs.
def verify_xml(xml, key_file):

  doc = libxml2.parseDoc(xml)
  if doc is None or doc.getRootElement() is None:
    cleanup(doc)
    raise saml2.Error("Error: unable to parse file \"%s\"" % tmpl_file)

  # Find start node
  node = xmlsec.findNode(doc.getRootElement(),
                         xmlsec.NodeSignature, xmlsec.DSigNs)

  # Create signature context, we don't need keys manager in this example
  dsig_ctx = xmlsec.DSigCtx()
  if dsig_ctx is None:
    cleanup(doc)
    raise saml2.Error("Error: failed to create signature context")

  # Load public key, assuming that there is not password
  if key_file.endswith(".der"):
    key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatDer,
                                  None, None, None)
  else:
    key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                  None, None, None)
  
  if key is None:
    cleanup(doc, dsig_ctx)
    raise saml2.Error("Error: failed to load public key from \"%s\"" % key_file)

  dsig_ctx.signKey = key

  # Set key name to the file name, this is just an example!
  if key.setName(key_file) < 0:
    cleanup(doc, dsig_ctx)
    raise saml2.Error("Error: failed to set key name for key from \"%s\"" % key_file)

  # Verify signature
  if dsig_ctx.verify(node) < 0:
    cleanup(doc, dsig_ctx)
    raise saml2.Error("Error: signature verify")

  # Print verification result to stdout
  if dsig_ctx.status == xmlsec.DSigStatusSucceeded:
    ret = 0
  else:
    ret = -1

  # Success
  cleanup(doc, dsig_ctx)
  return ret

def sign(xml, key_file, cert_file=None):
  lib_init()
  ret = sign_xml(xml, key_file, cert_file)
  lib_shutdown()
  return ret

# Signs the xml_file using private key from key_file and dynamicaly
# created enveloped signature template.
# Returns 0 on success or a negative value if an error occurs.
def sign_xml(xml, key_file, cert_file=None):

  # Load template
  doc = libxml2.parseDoc(xml)
  if doc is None or doc.getRootElement() is None:
    cleanup(doc)
    raise saml2.Error("Error: unable to parse string \"%s\"" % xml)

  node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature,
                         xmlsec.DSigNs)

  if node is None:
    cleanup(doc)
    raise saml2.Error("Error: start node not found.")

  # Create signature context, we don't need keys manager in this example
  dsig_ctx = xmlsec.DSigCtx()
  if dsig_ctx is None:
    cleanup(doc)
    raise saml2.Error("Error: failed to create signature context")

  # Load private key, assuming that there is not password
  key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                None, None, None)
  if key is None:
    cleanup(doc, dsig_ctx)
    raise saml2.Error(
      "Error: failed to load private pem key from \"%s\"" % key_file)
  dsig_ctx.signKey = key

  if cert_file is not None:
    if xmlsec.cryptoAppKeyCertLoad(
      dsig_ctx.signKey, cert_file, xmlsec.KeyDataFormatPem) < 0:
      cleanup(doc, dsig_ctx)
      raise saml2.Error(
        "Error: failed to load cert pem from \"%s\"" % cert_file)
  else:
    pass
    
  # Set key name to the file name, this is just an example!
  if key.setName(key_file) < 0:
    cleanup(doc, dsig_ctx)
    raise saml2.Error(
      "Error: failed to set key name for key from \"%s\"" % key_file)
    return cleanup(doc, dsig_ctx)

  # Sign the template
  if dsig_ctx.sign(node) < 0:
    cleanup(doc, dsig_ctx)
    raise saml2.Error("Error: signature failed")

  # signed document to string
  ret = doc.__str__()

  # Success
  cleanup(doc, dsig_ctx, 1)

  return ret

def cleanup(doc=None, dsig_ctx=None, res=-1):
  if dsig_ctx is not None:
    dsig_ctx.destroy()
  if doc is not None:
    doc.freeDoc()
  return res
