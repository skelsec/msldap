
def list_str(x):
    return [e.decode() for e in x ]

def list_int(x):
    return [int(e) for e in x ]

def list_str_one(x):
    return x[0].decode()

LDAP_RESULT_TYPES = {
    'supportedCapabilities' : list_str,
    'serverName' : list_str_one,
    'ldapServiceName': list_str_one,
    'dnsHostName' : list_str_one,
    'supportedSASLMechanisms' : list_str,
    'supportedLDAPPolicies' : list_str,
    'supportedLDAPVersion' : list_int,
    'supportedControl' : list_str,
    'rootDomainNamingContext' : list_str_one,
    'configurationNamingContext' : list_str_one,
    'schemaNamingContext' : list_str_one,
    'defaultNamingContext' : list_str_one,
    'namingContexts' : list_str,
    'dsServiceName' : list_str_one,
    'subschemaSubentry' : list_str_one,
}

def convert_result(x):
    t = {}
    for e in x:
        k = e['type'].decode()
        print('k: %s' % k)
        if k in LDAP_RESULT_TYPES:
            t[k] = LDAP_RESULT_TYPES[k](e['attributes'])
        else:
            t[k] = e[1]['attributes']
    return t