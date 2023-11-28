import json
from tqdm import tqdm

def compare_links(l1, l2):
    for entry in l1:
        if not isinstance(entry, dict):
            print('TYPE_MISSMATCH', f"{entry} not a dict")
        else:
            for ce in l2:
                if ce['GUID'] == entry['GUID'] and ce['IsEnforced'] == entry['IsEnforced']:
                    break
            else:
                print('MISSING_LINK', f"{entry['GUID']} not in l2")

def compare_aces(l1, l2):
    for entry in l1:
        if not isinstance(entry, dict):
            print('TYPE_MISSMATCH', f"{entry} not a dict")
        else:
            for ce in l2:
                if ce['PrincipalSID'] == entry['PrincipalSID'] and ce['PrincipalType'] == entry['PrincipalType'] and ce['RightName'] == entry['RightName'] and ce['IsInherited'] == entry['IsInherited']:
                    #print('MATCH', f"{entry['PrincipalSID']} in l2")
                    break
            else:
                print('MISSING_ACE', f"{entry['PrincipalSID']} not in l2")

def compare_objlist(ctype, l1, l2):
    for entry in l1:
        if not isinstance(entry, dict):
            print('TYPE_MISSMATCH %s' % ctype, f"{entry} not a dict")
        else:
            for ce in l2:
                if ce['ObjectIdentifier'] == entry['ObjectIdentifier'] and ce['ObjectType'] == entry['ObjectType']:
                    #print('MATCH', f"{entry['ObjectIdentifier']} in l2")
                    break
            else:
                print('MISSING_%s' % ctype, f"{entry['ObjectIdentifier']} not in l2")


def compare_dict(label, d1, d2):
    #print('Checking %s' % label)
    for k in d1:
        #print('Checking %s -> %s' % (label, k))
        if k not in d2:
            yield ('MISSING_PARAM',k, f"{k} not in dict")
        if isinstance(d1[k], (str, int, float, bool)):
            if k not in d2:
                yield ('MISSING_PARAM', k, f"'{k}' not in dict")
            else:
                #print('Checking %s -> %s Exists!' % (label, k))
                if d2[k] != d1[k]:
                    yield ('NOT_EQ', k, f"'{k}' value not equal in dict. D1: {d1[k]} D2: {d2[k]}")
                #else:
                #    print('Checking %s -> %s Matches!' % (label, k))
        if isinstance(d1[k], list):
            if k not in d2:
                yield ('MISSING_PARAM', k, f"'{k}' not in dict")
            else:
                #print('Checking %s -> %s Exists!' % (label, k))
                if isinstance(d2[k], list):
                    if(len(d1[k]) != len(d2[k])):
                        yield ('NOT_EQ', k, f"'{k}' length not equal in dict. D1: d1[{k}] D2: d2[{k}]")
                    if k == 'Links':
                        compare_links(d1[k], d2[k])
                    elif k == 'Aces':
                        compare_aces(d1[k], d2[k])
                    elif k in ['ChildObjects', 'Members']:
                        compare_objlist(k,d1[k], d2[k])
                    else:
                        for i, item in enumerate(d1[k]):
                            if i >= len(d2[k]):
                                yield ('MISSING_PARAM', f"'{k}[{i}]'", f"'{k}[{i}]' not in dict")
                            else:
                                for k2 in item:
                                    if k2 not in d2[k][i]:
                                        yield ('MISSING_PARAM', f"'{k}[{i}][{k2}]'", f"'{k}[{i}][{k2}]' not in dict")
                else:
                    yield ('TYPE_MISMATCH', k, f"{k} not a list in dict. D1: {d1[k]} D2: {d2[k]}")
        if isinstance(d1[k], dict):
            if k not in d2:
                yield ('MISSING_PARAM', k, f"'{k}' not in dict")
            else:
                if isinstance(d2[k], dict):
                    compare_dict('%s -> %s' % (label, k), d1[k], d2[k])
                else:
                    yield ('TYPE_MISMATCH', k, f"{k} not a dict in dict")


filelist = [
    ('/home/webdev/Desktop/comparer/good/good_domains.json', '/home/webdev/Desktop/projects/msldap/domains.json'),
    ('/home/webdev/Desktop/comparer/good/good_groups.json', '/home/webdev/Desktop/projects/msldap/groups.json'),
    #('/home/webdev/Desktop/comparer/good/good_users.json', '/home/webdev/Desktop/projects/msldap/users.json'),
    ('/home/webdev/Desktop/comparer/good/good_computers.json', '/home/webdev/Desktop/projects/msldap/computers.json'),
    ('/home/webdev/Desktop/comparer/good/good_containers.json', '/home/webdev/Desktop/projects/msldap/containers.json'),
    ('/home/webdev/Desktop/comparer/good/good_gpos.json', '/home/webdev/Desktop/projects/msldap/gpos.json'),
    ('/home/webdev/Desktop/comparer/good/good_ous.json', '/home/webdev/Desktop/projects/msldap/ous.json'),
]

for filetuple in filelist:
    print('Comparing %s to %s' % filetuple)
    with open(filetuple[0]) as f:
        f.seek(3)
        json2 = json.load(f)

    print('Loading test file...')
    with open(filetuple[1]) as f:
        json1 = json.load(f)

    bypass_diff = {
        'NOT_EQ': {
            'whencreated': 1
        }
    }

    total = len(json2['data'])
    pbar = tqdm(total=total)
    for guser in json2['data']:
        pbar.update(1)
        for user in json1['data']:
            if user['ObjectIdentifier'] == guser['ObjectIdentifier']:
                #print(user['Aces'])
                #print(guser['Aces'])
                for diff_type, param_name, desc in compare_dict(guser['ObjectIdentifier'], guser, user):
                    if diff_type in bypass_diff:
                        if param_name in bypass_diff[diff_type]:
                            continue
                    print('%s -> %s' % (user['ObjectIdentifier'], desc))
                    
                #input()

