from msldap import logger

WELLKNOWN_SIDS = {
        "S-1-0": ("Null Authority", "USER"),
        "S-1-0-0": ("Nobody", "USER"),
        "S-1-1": ("World Authority", "USER"),
        "S-1-1-0": ("Everyone", "GROUP"),
        "S-1-2": ("Local Authority", "USER"),
        "S-1-2-0": ("Local", "GROUP"),
        "S-1-2-1": ("Console Logon", "GROUP"),
        "S-1-3": ("Creator Authority", "USER"),
        "S-1-3-0": ("Creator Owner", "USER"),
        "S-1-3-1": ("Creator Group", "GROUP"),
        "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
        "S-1-3-3": ("Creator Group Server", "COMPUTER"),
        "S-1-3-4": ("Owner Rights", "GROUP"),
        "S-1-4": ("Non-unique Authority", "USER"),
        "S-1-5": ("NT Authority", "USER"),
        "S-1-5-1": ("Dialup", "GROUP"),
        "S-1-5-2": ("Network", "GROUP"),
        "S-1-5-3": ("Batch", "GROUP"),
        "S-1-5-4": ("Interactive", "GROUP"),
        "S-1-5-6": ("Service", "GROUP"),
        "S-1-5-7": ("Anonymous", "GROUP"),
        "S-1-5-8": ("Proxy", "GROUP"),
        "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
        "S-1-5-10": ("Principal Self", "USER"),
        "S-1-5-11": ("Authenticated Users", "GROUP"),
        "S-1-5-12": ("Restricted Code", "GROUP"),
        "S-1-5-13": ("Terminal Server Users", "GROUP"),
        "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
        "S-1-5-15": ("This Organization", "GROUP"),
        "S-1-5-17": ("IUSR", "USER"),
        "S-1-5-18": ("Local System", "USER"),
        "S-1-5-19": ("NT Authority", "USER"),
        "S-1-5-20": ("Network Service", "USER"),
        "S-1-5-80-0": ("All Services ", "GROUP"),
        "S-1-5-32-544": ("Administrators", "GROUP"),
        "S-1-5-32-545": ("Users", "GROUP"),
        "S-1-5-32-546": ("Guests", "GROUP"),
        "S-1-5-32-547": ("Power Users", "GROUP"),
        "S-1-5-32-548": ("Account Operators", "GROUP"),
        "S-1-5-32-549": ("Server Operators", "GROUP"),
        "S-1-5-32-550": ("Print Operators", "GROUP"),
        "S-1-5-32-551": ("Backup Operators", "GROUP"),
        "S-1-5-32-552": ("Replicators", "GROUP"),
        "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
        "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
        "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
        "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
        "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
        "S-1-5-32-559": ("Performance Log Users", "GROUP"),
        "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
        "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
        "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
        "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
        "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
        "S-1-5-32-573": ("Event Log Readers", "GROUP"),
        "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
        "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
        "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
        "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
        "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
        "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-582": ("Storage Replica Administrators", "GROUP")
    }

def resolve_aces(aces, domainname, domainsid, sidcache):
    aces_out = []
    for ace in aces:
        out = {
            'RightName': ace['rightname'],
            'IsInherited': ace['inherited']
        }
        # Is it a well-known sid?
        if ace['sid'] in WELLKNOWN_SIDS:
            out['PrincipalSID'] = u'%s-%s' % (domainname.upper(), ace['sid'])
            out['PrincipalType'] = WELLKNOWN_SIDS[ace['sid']][1].capitalize()
        else:
            linkitem = sidcache.get(ace['sid'])
            if linkitem is None:
                logger.debug('[EXT-BH] Cache miss for %s' % ace['sid'])
                entry = {
                    'type': 'Base',
                    'objectid': ace['sid']
                }
                linkitem = {
                    "ObjectIdentifier": entry['objectid'],
                    "ObjectType": entry['type'].capitalize()
                }
                sidcache[ace['sid']] = linkitem
            out['PrincipalSID'] = ace['sid']
            out['PrincipalType'] = linkitem['ObjectType'].capitalize()
        
        for tace in aces_out:
            if out['PrincipalSID'] == tace['PrincipalSID'] and out['PrincipalType'] == tace['PrincipalType'] and out['RightName'] == tace['RightName'] and out['IsInherited'] == tace['IsInherited']:
                break
        else:
            aces_out.append(out)
    return aces_out

def resolve_sid(sid, domainname, domainsid, sidcache):
    # Resolve SIDs for SID history purposes
    out = {}
    # Is it a well-known sid?
    if sid in WELLKNOWN_SIDS:
        out['ObjectIdentifier'] = u'%s-%s' % (domainname.upper(), sid)
        out['ObjectType'] = WELLKNOWN_SIDS[sid][1].capitalize()
    else:
        try:
            linkitem = sidcache.get(sid)
        except KeyError:
            # Look it up instead
            # Is this SID part of the current domain? If not, use GC
            #use_gc = not sid.startswith(domainsid)
            #ldapentry = self.resolver.resolve_sid(sid, use_gc)
            # Couldn't resolve...
            #if not ldapentry:
            #    logger.debug('Could not resolve SID: %s', sid)
            #    # Fake it
            #    entry = {
            #        'type': 'Base',
            #        'objectid':sid
            #    }
            #else:
            #    entry = ADUtils.resolve_ad_entry(ldapentry)
            entry = {
                'type': 'Base',
                'objectid':sid
            }
            linkitem = {
                "ObjectIdentifier": entry['objectid'],
                "ObjectType": entry['type'].capitalize()
            }
            # Entries are cached regardless of validity - unresolvable sids
            # are not likely to be resolved the second time and this saves traffic
            sidcache.put(sid, linkitem)
        out['ObjectIdentifier'] = sid
        out['ObjectType'] = linkitem['ObjectType']
    return out
