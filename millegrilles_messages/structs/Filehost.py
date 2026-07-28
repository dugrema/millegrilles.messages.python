import logging
from typing import Optional
from dataclasses import dataclass
from urllib.parse import urlparse, ParseResult, urljoin

from millegrilles_messages.messages import Constantes

LOGGER = logging.getLogger(__name__)


@dataclass
class FilehostConnectionParams:
    url: ParseResult
    method: str


class Filehost:

    def __init__(self, filehost_id: str, url_external: str, tls_external: str):
        self.filehost_id = filehost_id
        self.instance_id: Optional[str] = None
        self.deleted: Optional[bool] = None
        self.sync_active: Optional[bool] = None
        url_external_parsed = urlparse(url_external)
        self.filehost_params = FilehostConnectionParams(url_external_parsed, tls_external)

    # def export_for_client(self):
    #     if self.url_external:
    #         url = f'{self.url_external}/filehost'
    #         tls = self.tls_external
    #     else:
    #         url = 'https://localhost/filehost'   # Tells the app to use the connexion url
    #         tls = 'external'                     # Means standard internet CAs like Verisign, ZeroSSl, etc.
    #
    #     return {
    #         'instance_id': self.instance_id,
    #         'filehost_id': self.filehost_id,
    #         'url': url,
    #         'tls': tls,
    #     }
    #
    # def to_dict(self):
    #     return {
    #         'filehost_id': self.filehost_id,
    #         'url_internal': self.url_internal,
    #         'url_external': self.url_external,
    #         'tls_external': self.tls_external,
    #         'instance_id': self.instance_id,
    #         'deleted': self.deleted,
    #         'sync_active': self.sync_active,
    #     }
    #
    # @staticmethod
    # def load_from_dict(value: dict):
    #     filehost_id = value['filehost_id']
    #     filehost = Filehost(filehost_id)
    #
    #     filehost.url_internal = value.get('url_internal')
    #     filehost.url_external = value.get('url_external')
    #     filehost.tls_external = value.get('tls_external')
    #     filehost.instance_id = value.get('instance_id')
    #     filehost.deleted = value.get('deleted')
    #     filehost.sync_active = value.get('sync_active')
    #
    #     return filehost
    #
    # @staticmethod
    # def init_new(filehost_id: str, instance_id: str, url: str):
    #     filehost = Filehost(filehost_id)
    #     filehost.url_internal = url
    #     filehost.instance_id = instance_id
    #     filehost.deleted = False
    #     filehost.sync_active = True
    #     return filehost


async def load_fiche(context) -> Optional[dict]:
    idmg = context.signing_key.enveloppe.idmg
    producer = await context.get_producer()
    fiche_response = await producer.request({'idmg': idmg}, 'CoreTopologie', 'ficheMillegrille',
                                            exchange=Constantes.SECURITE_PUBLIC)

    if fiche_response.parsed.get('applicationsV2'):
        return fiche_response.parsed
    else:
        LOGGER.error("Error loading fiche information")
    return None


async def load_filehost_configuration(context) -> Optional[Filehost]:
    producer = await context.get_producer()
    response = await producer.request(
        dict(), 'CoreTopologie', 'getFilehostForInstance', exchange="1.public")

    try:
        filehost_response = response.parsed
        filehost_dict = filehost_response['filehost']
        filehost_id = filehost_dict['filehost_id']
        if filehost_dict.get('instance_id'):
            # Managed filehost for the same Millegrille
            tls_method = 'millegrille'
            instance_id = filehost_dict['instance_id']
            if context.instance_id == instance_id:
                # This is on the local docker instance
                if context.configuration.dev:
                    # In dev, so reverting to localhost on mtls port
                    url = 'https://localhost:444'
                else:
                    # Same docker host, hard-coding access
                    url = 'https://filehost:1443'
            else:
                # Different host, use system card to get hostname:port
                fiche = await load_fiche(context)
                instance = fiche['instances'][instance_id]
                if instance:
                    try:
                        url = instance['domaines'][0]
                        mtls_port = instance['ports']['https_mtls']
                        url = f'https://{url}:{mtls_port}'
                    except KeyError:
                        LOGGER.info("Error reading from system card, falling back to trying direct local access")
                        url = None
                else:
                    LOGGER.warning('No filehost found, falling back to trying direct local access')
                    url = None
        elif filehost_dict.get('url_external'):
            # Unmanaged external filehost
            url = filehost_dict['url_external']
            tls_method = filehost_dict['tls_external']
        else:
            LOGGER.warning('No filehost found, falling back to trying direct local access')
            url = None
            tls_method = None

        if not url:
            # Fallback to internal filehost (same docker instance)
            url = 'https://filehost:1443'
            tls_method = 'millegrille'
        if not tls_method:
            tls_method = 'external'

        filehost = Filehost(filehost_id, url, tls_method)
        filehost.instance_id = filehost_dict['instance_id']

        return filehost
    except:
        LOGGER.exception("Error loading filehost")
        return None
