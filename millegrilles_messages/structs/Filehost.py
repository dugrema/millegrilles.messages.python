import asyncio
import datetime

from typing import Optional


class Filehost:

    def __init__(self, filehost_id: str):
        self.filehost_id = filehost_id
        self.url_internal: Optional[str] = None
        self.url_external: Optional[str] = None
        self.tls_external: Optional[str] = None
        self.instance_id: Optional[str] = None
        self.deleted: Optional[bool] = None
        self.sync_active: Optional[bool] = None

    def export_for_client(self):
        if self.url_external:
            url = f'{self.url_external}/filehost'
            tls = self.tls_external
        else:
            url = 'https://localhost/filehost'   # Tells the app to use the connexion url
            tls = 'external'                     # Means standard internet CAs like Verisign, ZeroSSl, etc.

        return {
            'instance_id': self.instance_id,
            'filehost_id': self.filehost_id,
            'url': url,
            'tls': tls,
        }

    def to_dict(self):
        return {
            'filehost_id': self.filehost_id,
            'url_internal': self.url_internal,
            'url_external': self.url_external,
            'tls_external': self.tls_external,
            'instance_id': self.instance_id,
            'deleted': self.deleted,
            'sync_active': self.sync_active,
        }

    @staticmethod
    def load_from_dict(value: dict):
        filehost_id = value['filehost_id']
        filehost = Filehost(filehost_id)

        filehost.url_internal = value.get('url_internal')
        filehost.url_external = value.get('url_external')
        filehost.tls_external = value.get('tls_external')
        filehost.instance_id = value.get('instance_id')
        filehost.deleted = value.get('deleted')
        filehost.sync_active = value.get('sync_active')

        return filehost

    @staticmethod
    def init_new(filehost_id: str, instance_id: str, url: str):
        filehost = Filehost(filehost_id)
        filehost.url_internal = url
        filehost.instance_id = instance_id
        filehost.deleted = False
        filehost.sync_active = True
        return filehost
