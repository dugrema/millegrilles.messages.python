from cryptography.x509.base import CertificateBuilder

from millegrilles_messages.certificats.Generes import EnveloppeCsr
from millegrilles_messages.messages.CleCertificat import CleCertificat
from millegrilles_messages.messages import Constantes
from millegrilles_messages.certificats.Generes import ajouter_roles, ajouter_user_id, ajouter_delegation_globale


def signer_usager(cle_intermediaire: CleCertificat, csr_pem: str, parametres: dict):
    enveloppe_csr = EnveloppeCsr.from_str(csr_pem)
    builder = CertificateBuilder()

    common_name = enveloppe_csr.cn
    nom_usager: str = parametres['nom_usager']
    if common_name != nom_usager:
        raise Exception(
            "Nom usager du CSR (%s) ne correspond par a celui de la commande (%s)" % (common_name, nom_usager))

    role = 'usager'
    roles = [role, 'navigateur']

    if parametres.get('compte_prive') is True:
        roles.append('compte_prive')

    builder = ajouter_roles(builder, roles)

    # On doit recuperer le user_id en parametres
    user_id: str = parametres['user_id']
    builder = ajouter_user_id(builder, user_id)

    try:
        delegation_globale = parametres['delegation_globale']
        builder = ajouter_delegation_globale(builder, delegation_globale)
    except (AttributeError, KeyError):
        pass  # OK

    #         try:
    #             delegations_domaines = kwargs['delegations_domaines']
    #             custom_oid_delegation_domaines = ConstantesGenerateurCertificat.MQ_DELEGATION_DOMAINES_OID
    #             builder = builder.add_extension(
    #                 x509.UnrecognizedExtension(custom_oid_delegation_domaines, delegations_domaines.encode('utf-8')),
    #                 critical=False
    #             )
    #         except (AttributeError, KeyError):
    #             pass  # OK
    #
    #         try:
    #             delegations_sousdomaines = kwargs['delegations_sousdomaines']
    #             custom_oid_delegation_sousdomaines = ConstantesGenerateurCertificat.MQ_DELEGATIONS_SOUSDOMAINES_OID
    #             builder = builder.add_extension(
    #                 x509.UnrecognizedExtension(custom_oid_delegation_sousdomaines, delegations_sousdomaines.encode('utf-8')),
    #                 critical=False
    #             )
    #         except (AttributeError, KeyError):
    #             pass  # OK

    enveloppe_certificat = enveloppe_csr.signer(cle_intermediaire, role, builder=builder)

    return enveloppe_certificat
