import re


def soundex(string, scale=4):
    string = string.upper()
    code = string[0]
    string = re.sub(r'[AEIOUYHW]', '', string)
    chr_key = {'BFPV': '1', 'CGJKQSXZ': '2', 'DT': '3', 'L': '4', 'MN': '5', 'R': '6'}

    for c in string[1:]:
        for k, v in chr_key.items():
            if (c in k) and (v != code[-1]):
                code += v
                break

    return code.ljust(scale, '0')


def soundex_compare(val1, val2):
    return soundex(val1) == soundex(val2)
