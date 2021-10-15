#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import binascii
import base64
import xml.sax.saxutils as saxutils


class BurpExtender(IBurpExtender, IScannerCheck):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("SecretFinder")
        self._callbacks.registerScannerCheck(self)
        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # add your regex here
    regexs = {
        'google_api' : 'AIza[0-9A-Za-z-_]{35}',
        'google_cloud_platform_auth' : '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'google_cloud_platform_api' : '[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}',
        'amazon_secret_key_1' : '((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})', 
        'firebase' : 'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'google_oauth' : 'ya29\.[0-9A-Za-z\-_]+',
        'amazon_mws_auth_toke' : 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'amazon_aws_url' : 's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
        'facebook_access_token' : 'EAACEdEose0cBA[0-9A-Za-z]+',
        #'authorization_basic' : 'basic\s*[a-zA-Z0-9=:_\+\/-]+',
        #'authorization_bearer' : 'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
        'azure_api_gateway' : 'Ocp-Apim-Subscription-Key',
        'azure_blob_storage' : 'blob.core.windows.net',
        'azure_blob_storage_sas' : 'sv=2019-12-12&ss=bfqt&srt=sco',
        'api_endpoint_1' : 'apiEndpoint:',
        'api_endpoint_2' : 'apiEndpoint\s*=',
        'api_endpoint_3' : 'apiUrl:',
        'authorization_api_1' : 'apikey:\s*',
        'authorization_api_2' : 'api-key:\s*',
        'authorization_api_3' : 'api_key:\s*',
        'authorization_api_4' : 'apikey\s*=',
        'authorization_api_5' : 'api-key\s*=',
        'authorization_api_6' : 'api_key\s*=',
        'authorization_api_7' : 'apiKey = ',
        'mailgun_api_key' : 'key-[0-9a-zA-Z]{32}',
        'twilio_api_key' : 'SK[0-9a-fA-F]{32}',
        'paypal_braintree_access_token' : 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'stripe_standard_api' : 'sk_live_[0-9a-zA-Z]{24}',
        'stripe_restricted_api' : 'rk_live_[0-9a-zA-Z]{24}',
        'github_access_token' : '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
        'rsa_private_key' : '-----BEGIN RSA PRIVATE KEY-----',
        'ssh_dsa_private_key' : '-----BEGIN DSA PRIVATE KEY-----',
        'ssh_dc_private_key' : '-----BEGIN EC PRIVATE KEY-----',
        'pgp_private_block' : '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'private_key': '-----BEGIN PRIVATE KEY-----'
        #'json_web_token' : 'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*'
    }
    #regex = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
    regex = r"(%%regex%%)"
    issuename = "SecretFinder: %s"
    issuelevel = "High"
    issuedetail = r"""Potential Secret Found: <b>%%regex%%</b>
    <br><br><b>Note:</b> Please note that some of these issues could be false positives, a manual review is recommended."""

    def doActiveScan(self, baseRequestResponse,pa):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]), 
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.ssuelevel, 
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]),
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])), 
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._mime_type = self._helpers.analyzeResponse(self._requestResponse.getResponse()).getStatedMimeType()
        return

    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)
        
        # Compile the regular expression, telling Python to ignore EOL/LF
        myre = re.compile(regex, re.VERBOSE | re.IGNORECASE)

        # Using the regular expression, find all occurrences in the base response
        match_vals = myre.findall(self._helpers.bytesToString(response))

        # For each matched value found, find its start position, so that we can create
        # the offset needed to apply appropriate markers in the resulting Scanner issue
        for ref in match_vals:
            offsets = []
            start = self._helpers.indexOf(response,
                                ref, True, 0, responseLength)
            offset[0] = start
            offset[1] = start + len(ref)
            offsets.append(offset)
           
            # Create a ScanIssue object and append it to our list of issues, marking
            # the matched value in the response.
            scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                    self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
                    [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                    issuename, issuelevel, issuedetail.replace(r"%%regex%%", ref)))

        return (scan_issues)

class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"