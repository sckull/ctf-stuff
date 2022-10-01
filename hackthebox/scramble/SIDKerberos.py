#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys
import re
import struct
from datetime import datetime

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.examples import logger
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection

class GetSIDs:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''        
        self.__doKerberos = cmdLineOptions.k
        #[!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__requestUser = cmdLineOptions.user
        self.__all = cmdLineOptions.all

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        # Let's calculate the header and format
        self.__header = ["Name", "SID"]
        # Since we won't process all rows at once, this will be fixed lengths
        self.__colLen = [20, 30]
        self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])    

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t    

    def sidRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        sAMAccountName = ''
        objectSid = ''
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                        # User Account
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')                
                elif str(attribute['type']) == 'objectSid':
                    objectSid = self.sid_to_str(attribute['vals'][0])

            print((self.__outputFormat.format(*[sAMAccountName, objectSid])))
            #print(sAMAccountName, objectSid)
        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error('Skipping item, cannot process due to error %s' % str(e))
            pass
    
    # convert sid to string
    def sid_to_str(self, sid):
        try:            
            if str is not bytes:
                # revision
                revision = int(sid[0])
                # count of sub authorities
                sub_authorities = int(sid[1])
                # big endian
                identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
                # If true then it is represented in hex
                if identifier_authority >= 2 ** 32:
                    identifier_authority = hex(identifier_authority)
                # loop over the count of small endians
                sub_authority = '-' + '-'.join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little')) for i in range(sub_authorities)])            
            objectSid = 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority

            return objectSid
        except Exception:
            pass

        return sid

    def run(self):
        if self.__kdcHost is not None:
            self.__target = self.__kdcHost

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, kdcHost=self.__kdcIP)                

        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, kdcHost=self.__kdcIP)
            else:
                if self.__kdcIP is not None and self.__kdcHost is not None:
                    logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They must match exactly each other")
                raise

        logging.info('Querying %s for information about domain.' % self.__target)
        # Print header
        print((self.__outputFormat.format(*self.__header)))
        print(('  '.join(['-' * itemLen for itemLen in self.__colLen])))

        # Building the search filter
        if self.__all:
            searchFilter = "(&(objectclass=user)(objectSid=*)(!(ObjectClass=foreignSecurityPrincipal)))"

        if self.__requestUser is not None:
            searchFilter += '(sAMAccountName:=%s))' % self.__requestUser
        else:
            searchFilter += ')'

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)            
            # sidRecord
            ldapConnection.search(searchFilter="(&(objectClass=user)(objectSid=*)(!(ObjectClass=foreignSecurityPrincipal)))",
                                    sizeLimit=0,searchControls = [sc], perRecordCallback=self.sidRecord)
        except ldap.LDAPSearchError:
                raise

        ldapConnection.close()

# Process command-line arguments.
if __name__ == '__main__':
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for users data")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-user', action='store', metavar='username', help='Requests data for specific user ')
    parser.add_argument('-all', action='store_true', help='Return all users, including those with no email '
                                                           'addresses and disabled accounts. When used with -user it '
                                                          'will return user\'s info even if the account is disabled')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')    
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = re.compile('(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?').match(options.target).groups('')

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    try:
        executer = GetSIDs(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print((str(e)))
