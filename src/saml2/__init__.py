#!/usr/bin/python
#
# Copyright (C) 2006 Google Inc.
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

"""Contains objects used with SAML-2."""

__author__ = 'api.jscudder (Jeffrey Scudder)'

"""Contains base classes representing Saml elements.

  These codes were originally written by Jeffrey Scudder for
  representing Atom elements. Takashi Matsuo had added some codes, and
  changed some.

  Module objective: provide data classes for Saml constructs. These
  classes hide the XML-ness of Saml and provide a set of native Python
  classes to interact with.

  Conversions to and from XML should only be necessary when the Saml classes
  "touch the wire" and are sent over HTTP. For this reason this module 
  provides  methods and functions to convert Saml classes to and from strings.

  SamlBase: A foundation class on which Saml classes are built. It 
      handles the parsing of attributes and children which are common to all
      Saml classes. By default, the SamlBase class translates all XML child 
      nodes into ExtensionElements.

  ExtensionElement: XML which is not part of the Saml specification,
      these are called extension elements. If a classes parser
      encounters an unexpected XML construct, it is translated into an
      ExtensionElement instance. ExtensionElement is designed to fully
      capture the information in the XML. Child nodes in an XML
      extension are turned into ExtensionElements as well.
"""

try:
  from xml.etree import cElementTree as ElementTree
except ImportError:
  try:
    import cElementTree as ElementTree
  except ImportError:
    from elementtree import ElementTree

SAML_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAML_TEMPLATE = '{urn:oasis:names:tc:SAML:2.0:assertion}%s'
XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'

NAMEID_FORMAT_EMAILADDRESS = (
  "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")
URN_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
NAME_FORMAT_UNSPECIFIED = (
  "urn:oasis:names:tc:SAML:2.0:attrnam-format:unspecified")
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrnam-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrnam-format:basic"
SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

DECISION_TYPE_PERMIT = "Permit"
DECISION_TYPE_DENY = "Deny"
DECISION_TYPE_INDETERMINATE = "Indeterminate"

V2 = "2.0"

def CreateClassFromXMLString(target_class, xml_string):
  """Creates an instance of the target class from the string contents.
  
  Args:
    target_class: class The class which will be instantiated and populated
        with the contents of the XML. This class must have a _tag and a
        _namespace class variable.
    xml_string: str A string which contains valid XML. The root element
        of the XML string should match the tag and namespace of the desired
        class.

  Returns:
    An instance of the target class with members assigned according to the
    contents of the XML - or None if the root XML tag and namespace did not
    match those of the target class.
  """
  tree = ElementTree.fromstring(xml_string)
  return _CreateClassFromElementTree(target_class, tree)


def _CreateClassFromElementTree(target_class, tree, namespace=None, tag=None):
  """Instantiates the class and populates members according to the tree.

  Note: Only use this function with classes that have _namespace and _tag
  class members.

  Args:
    target_class: class The class which will be instantiated and populated
        with the contents of the XML.
    tree: ElementTree An element tree whose contents will be converted into
        members of the new target_class instance.
    namespace: str (optional) The namespace which the XML tree's root node must
        match. If omitted, the namespace defaults to the _namespace of the 
        target class.
    tag: str (optional) The tag which the XML tree's root node must match. If
        omitted, the tag defaults to the _tag class member of the target 
        class.

    Returns:
      An instance of the target class - or None if the tag and namespace of 
      the XML tree's root node did not match the desired namespace and tag.
  """
  if namespace is None:
    namespace = target_class._namespace
  if tag is None:
    tag = target_class._tag
  if tree.tag == '{%s}%s' % (namespace, tag):
    target = target_class()
    target._HarvestElementTree(tree)
    return target
  else:
    return None

class Error(Exception):
  """Exception class thrown by this module."""
  pass

class ExtensionElement(object):
  """Represents extra XML elements contained in Saml classes."""
  
  def __init__(self, tag, namespace=None, attributes=None, 
      children=None, text=None):
    """Constructor for EtensionElement

    Args:
      namespace: string (optional) The XML namespace for this element.
      tag: string (optional) The tag (without the namespace qualifier) for
          this element. To reconstruct the full qualified name of the element,
          combine this tag with the namespace.
      attributes: dict (optinal) The attribute value string pairs for the XML 
          attributes of this element.
      children: list (optional) A list of ExtensionElements which represent 
          the XML child nodes of this element.
    """

    self.namespace = namespace
    self.tag = tag
    self.attributes = attributes or {}
    self.children = children or []
    self.text = text
    
  def ToString(self):
    element_tree = self._TransferToElementTree(ElementTree.Element(''))
    return ElementTree.tostring(element_tree, encoding="UTF-8")
    
  def _TransferToElementTree(self, element_tree):
    if self.tag is None:
      return None
      
    if self.namespace is not None:
      element_tree.tag = '{%s}%s' % (self.namespace, self.tag)
    else:
      element_tree.tag = self.tag
      
    for key, value in self.attributes.iteritems():
      element_tree.attrib[key] = value
      
    for child in self.children:
      child._BecomeChildElement(element_tree)
      
    element_tree.text = self.text
      
    return element_tree

  def _BecomeChildElement(self, element_tree):
    """Converts this object into an etree element and adds it as a child node.

    Adds self to the ElementTree. This method is required to avoid verbose XML
    which constantly redefines the namespace.

    Args:
      element_tree: ElementTree._Element The element to which this object's XML
          will be added.
    """
    new_element = ElementTree.Element('')
    element_tree.append(new_element)
    self._TransferToElementTree(new_element)

  def FindChildren(self, tag=None, namespace=None):
    """Searches child nodes for objects with the desired tag/namespace.

    Returns a list of extension elements within this object whose tag
    and/or namespace match those passed in. To find all children in
    a particular namespace, specify the namespace but not the tag name.
    If you specify only the tag, the result list may contain extension
    elements in multiple namespaces.

    Args:
      tag: str (optional) The desired tag
      namespace: str (optional) The desired namespace

    Returns:
      A list of elements whose tag and/or namespace match the parameters
      values
    """

    results = []

    if tag and namespace:
      for element in self.children:
        if element.tag == tag and element.namespace == namespace:
          results.append(element)
    elif tag and not namespace:
      for element in self.children:
        if element.tag == tag:
          results.append(element)
    elif namespace and not tag:
      for element in self.children:
        if element.namespace == namespace:
          results.append(element)
    else:
      for element in self.children:
        results.append(element)

    return results
 
    
def ExtensionElementFromString(xml_string):
  element_tree = ElementTree.fromstring(xml_string)
  return _ExtensionElementFromElementTree(element_tree)


def _ExtensionElementFromElementTree(element_tree):
  element_tag = element_tree.tag
  if '}' in element_tag:
    namespace = element_tag[1:element_tag.index('}')]
    tag = element_tag[element_tag.index('}')+1:]
  else: 
    namespace = None
    tag = element_tag
  extension = ExtensionElement(namespace=namespace, tag=tag)
  for key, value in element_tree.attrib.iteritems():
    extension.attributes[key] = value
  for child in element_tree:
    extension.children.append(_ExtensionElementFromElementTree(child))
  extension.text = element_tree.text
  return extension


class ExtensionContainer(object):
  
  def __init__(self, extension_elements=None, extension_attributes=None,
      text=None):
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}
    self.text = text
 
  # Three methods to create an object from an ElementTree
  def _HarvestElementTree(self, tree):
    # Fill in the instance members from the contents of the XML tree.
    for child in tree:
      self._ConvertElementTreeToMember(child)
    for attribute, value in tree.attrib.iteritems():
      self._ConvertElementAttributeToMember(attribute, value)
    self.text = tree.text
    
  def _ConvertElementTreeToMember(self, child_tree, current_class=None):
    self.extension_elements.append(_ExtensionElementFromElementTree(
        child_tree))

  def _ConvertElementAttributeToMember(self, attribute, value):
    self.extension_attributes[attribute] = value

  # One method to create an ElementTree from an object
  def _AddMembersToElementTree(self, tree):
    for child in self.extension_elements:
      child._BecomeChildElement(tree)
    for attribute, value in self.extension_attributes.iteritems():
      tree.attrib[attribute] = value
    tree.text = self.text

  def FindExtensions(self, tag=None, namespace=None):
    """Searches extension elements for child nodes with the desired name.

    Returns a list of extension elements within this object whose tag
    and/or namespace match those passed in. To find all extensions in
    a particular namespace, specify the namespace but not the tag name.
    If you specify only the tag, the result list may contain extension
    elements in multiple namespaces.

    Args:
      tag: str (optional) The desired tag
      namespace: str (optional) The desired namespace

    Returns:
      A list of elements whose tag and/or namespace match the parameters
      values
    """

    results = []

    if tag and namespace:
      for element in self.extension_elements:
        if element.tag == tag and element.namespace == namespace:
          results.append(element)
    elif tag and not namespace:
      for element in self.extension_elements:
        if element.tag == tag:
          results.append(element)
    elif namespace and not tag:
      for element in self.extension_elements:
        if element.namespace == namespace:
          results.append(element)
    else:
      for element in self.extension_elements:
        results.append(element)

    return results
  

class SamlBase(ExtensionContainer):

  _children = {}
  _attributes = {}
  _child_order = []
  
  def __init__(self, extension_elements=None, extension_attributes=None,
      text=None):
    self.extension_elements = extension_elements or []
    self.extension_attributes = extension_attributes or {}
    self.text = text

  def _GetAllChildrenWithOrder(self):
    if len(self._child_order) > 0:
      for child in self._child_order:
        yield child
    else:
      for tag, values in self.__class__._children.iteritems():
        yield values[0]
    
  def _ConvertElementTreeToMember(self, child_tree):
    # Find the element's tag in this class's list of child members
    if self.__class__._children.has_key(child_tree.tag):
      member_name = self.__class__._children[child_tree.tag][0]
      member_class = self.__class__._children[child_tree.tag][1]
      # If the class member is supposed to contain a list, make sure the
      # matching member is set to a list, then append the new member
      # instance to the list.
      if isinstance(member_class, list):
        if getattr(self, member_name) is None:
          setattr(self, member_name, [])
        getattr(self, member_name).append(_CreateClassFromElementTree(
            member_class[0], child_tree))
      else:
        setattr(self, member_name, 
                _CreateClassFromElementTree(member_class, child_tree))
    else:
      ExtensionContainer._ConvertElementTreeToMember(self, child_tree)      

  def _ConvertElementAttributeToMember(self, attribute, value):
    # Find the attribute in this class's list of attributes. 
    if self.__class__._attributes.has_key(attribute):
      # Find the member of this class which corresponds to the XML attribute
      # (lookup in current_class._attributes) and set this member to the
      # desired value (using self.__dict__).
      setattr(self, self.__class__._attributes[attribute], value)
    else:
      ExtensionContainer._ConvertElementAttributeToMember(self, attribute, value)

  # Three methods to create an ElementTree from an object
  def _AddMembersToElementTree(self, tree):
    # Convert the members of this class which are XML child nodes. 
    # This uses the class's _children dictionary to find the members which
    # should become XML child nodes.
    for member_name in self._GetAllChildrenWithOrder():
      member = getattr(self, member_name)
      if member is None:
        pass
      elif isinstance(member, list):
        for instance in member:
          instance._BecomeChildElement(tree)
      else:
        member._BecomeChildElement(tree)
    # Convert the members of this class which are XML attributes.
    for xml_attribute, member_name in self.__class__._attributes.iteritems():
      member = getattr(self, member_name)
      if member is not None:
        tree.attrib[xml_attribute] = member
    # Lastly, call the ExtensionContainers's _AddMembersToElementTree to 
    # convert any extension attributes.
    ExtensionContainer._AddMembersToElementTree(self, tree)
    
  
  def _BecomeChildElement(self, tree):
    """

    Note: Only for use with classes that have a _tag and _namespace class 
    member. It is in AtomBase so that it can be inherited but it should
    not be called on instances of AtomBase.
    
    """
    new_child = ElementTree.Element('')
    tree.append(new_child)
    new_child.tag = '{%s}%s' % (self.__class__._namespace, 
                                self.__class__._tag)
    self._AddMembersToElementTree(new_child)

  def _ToElementTree(self):
    """

    Note, this method is designed to be used only with classes that have a 
    _tag and _namespace. It is placed in AtomBase for inheritance but should
    not be called on this class.

    """
    new_tree = ElementTree.Element('{%s}%s' % (self.__class__._namespace,
                                               self.__class__._tag))
    self._AddMembersToElementTree(new_tree)
    return new_tree

  def ToString(self):
    """Converts the Atom object to a string containing XML."""
    return ElementTree.tostring(self._ToElementTree(), encoding="UTF-8")

  def __str__(self):
    return self.ToString()


