#!/usr/bin/env python3
"""Decode SAML messages captured from the browser. Usage:
   saml_decode.py request  <SAMLRequest value>      (HTTP-Redirect: URL-decoded, base64, raw DEFLATE)
   saml_decode.py response <SAMLResponse value> [--summary]   (HTTP-POST: base64)"""
import base64, sys, urllib.parse, zlib
import xml.dom.minidom as minidom

NS = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion", "ds": "http://www.w3.org/2000/09/xmldsig#"}

def decode(kind, value):
    raw = base64.b64decode(urllib.parse.unquote(value))
    return zlib.decompress(raw, -15) if kind == "request" else raw   # -15 = raw DEFLATE, no zlib header

def summary(xml_bytes):
    from xml.etree import ElementTree as ET
    root = ET.fromstring(xml_bytes)          # parse only trusted local captures
    f = lambda path: (root.find(path, NS).text if root.find(path, NS) is not None else "-")
    nameid = root.find(".//saml:Subject/saml:NameID", NS)
    print("Issuer        :", f("saml:Issuer"))
    print("Destination   :", root.get("Destination"))
    print("Audience      :", f(".//saml:AudienceRestriction/saml:Audience"))
    print("NameID format :", nameid.get("Format") if nameid is not None else "-")
    print("email claim   :", f(".//saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']/saml:AttributeValue"))
    print("Signatures    :", len(root.findall(".//ds:Signature", NS)))

if __name__ == "__main__":
    kind, value = sys.argv[1], sys.argv[2]
    data = decode(kind, value)
    if "--summary" in sys.argv:
        summary(data)
    else:
        print(minidom.parseString(data).toprettyxml(indent="  "))
