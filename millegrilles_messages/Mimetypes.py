def est_video(mimetype: str):
    if not mimetype or not isinstance(mimetype, str):
        raise TypeError("mimetype doit etre une str")

    mimetype = mimetype.lower()

    if mimetype.startswith("video/"):
        return True

    MIMETYPE_VIDEOS = [
        "application/vnd.rn-realmedia",
        "application/vnd.rn-realplayer",
        "application/x-mplayer2",
        "application/x-shockwave-flash"
    ]

    return mimetype in MIMETYPE_VIDEOS
