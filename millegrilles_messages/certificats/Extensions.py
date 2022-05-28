from cryptography.x509 import ObjectIdentifier

# Liste des exchanges: millegrilles.middleware,millegrilles.noeud,etc.
EXCHANGES_OID = ObjectIdentifier('1.2.3.4.0')

# Liste de roles internes speciaux: transaction,deployeur,maitredescles
ROLES_OID = ObjectIdentifier('1.2.3.4.1')

# Liste des domaines: SenseursPassifs,GrosFichiers,MaitreDesCles,etc.
DOMAINES_OID = ObjectIdentifier('1.2.3.4.2')

# userId: ID unique de l'usager (ne pas confondre avec nomUsager dans CN)
USERID_OID = ObjectIdentifier('1.2.3.4.3')

# Role usager 'administrateur' qui s'applique a toute la MilleGrille.
# Valeurs: proprietaire, delegue
DELEGATION_GLOBALE_OID = ObjectIdentifier('1.2.3.4.4')

# Liste des domaines auxquels l'usager a un acces total (niveau 3.protege)
# Exemple : GrosFichiers,CoupDoeil,Publication
DELEGATION_DOMAINES_OID = ObjectIdentifier('1.2.3.4.5')

# Liste des sous-domaines auxquels l'usager a un acces total (niveau 3.protege)
# Exemple : Publication:forum_id=abc1234,GrosFichiers:uuid_collection=abcd1234;uuid_collection=abcd1235
DELEGATIONS_SOUSDOMAINES_OID = ObjectIdentifier('1.2.3.4.6')
