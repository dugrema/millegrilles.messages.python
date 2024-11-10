import aiohttp
import asyncio
import datetime
import logging

from ssl import SSLContext
from typing import Optional

BATCH_UPLOAD_DEFAULT = 1024 * 1024 * 1024 * 1   # 1 GB
CHUNK_SIZE = 64 * 1024
CONST_LIMITE_SAMPLES_UPLOAD = 50

LOGGER = logging.getLogger(__name__)


class UploadState:

    def __init__(self, fuuid: str, fp_file, size: int, stop_event: Optional[asyncio.Event] = None):
        self.fuuid = fuuid
        self.fp = fp_file
        self.stop_event = stop_event
        self.size = size
        self.position = 0
        self.samples = list()
        self.cb_activite = None
        self.done = False


async def feed_filepart(etat_upload: UploadState, limit=BATCH_UPLOAD_DEFAULT):
    taille_uploade = 0
    input_stream = etat_upload.fp

    chunk_size = CHUNK_SIZE
    if chunk_size > limit:
        chunk_size = limit

    debut_chunk = datetime.datetime.now()
    while taille_uploade < limit:
        if etat_upload.stop_event and etat_upload.stop_event.is_set():
            break  # Stopped

        chunk = await asyncio.to_thread(input_stream.read, chunk_size)
        if not chunk:
            etat_upload.done = True
            break

        yield chunk

        taille_uploade += len(chunk)
        etat_upload.position += len(chunk)

        if etat_upload.cb_activite:
            await etat_upload.cb_activite()

        # Calcule temps transfert chunk
        now = datetime.datetime.now()
        duree_transfert = now - debut_chunk
        etat_upload.samples.append({'duree': duree_transfert, 'taille': len(chunk)})
        while len(etat_upload.samples) > CONST_LIMITE_SAMPLES_UPLOAD:
            etat_upload.samples.pop(0)  # Detruire vieux samples

        debut_chunk = now


async def file_upload_parts(
        session: aiohttp.ClientSession,
        file_upload_url: str,
        etat_upload: UploadState,
        ssl_context: Optional[SSLContext] = None,
        batch_size=BATCH_UPLOAD_DEFAULT):

    put_headers = {'X-Total-Size': str(etat_upload.size)}

    batch_idx = 0

    while not etat_upload.done:
        position = etat_upload.position
        feeder_coro = feed_filepart(etat_upload, batch_size)
        session_coro = session.put(f'{file_upload_url}/{position}', ssl=ssl_context, headers=put_headers, data=feeder_coro)
        batch_idx += 1

        # Uploader chunk
        session_response = None
        try:
            session_response = await session_coro
        finally:
            if session_response is not None:
                session_response.release()
                if session_response.status == 412:
                    # Part already uploaded. Reposition file.
                    etat_upload.fp.seek(batch_idx * batch_size)
                    # Proceed to next part
                    continue
                session_response.raise_for_status()

    async with session.post(file_upload_url, ssl=ssl_context) as resp:
        resp.raise_for_status()

