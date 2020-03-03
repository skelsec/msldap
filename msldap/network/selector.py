
from msldap.network.tcp import MSLDAPTCPNetwork

class MSLDAPNetworkSelector:
    def __init__(self):
        pass
    
    @staticmethod
    def select(target):
        return MSLDAPTCPNetwork(target)