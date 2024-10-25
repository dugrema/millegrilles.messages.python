import pathlib

from millegrilles_messages.utils.TarStream import stream_path_to_tar

print("Test stream file")
with open('/tmp/out1.tar', 'wb') as output:
    stream_path_to_tar(pathlib.Path('/home/mathieu/Pictures/SaveOurLake galleries/Gallery/001.JPG'), output)

print("Test stream dir")
with open('/tmp/out2.tar', 'wb') as output:
    stream_path_to_tar(pathlib.Path('/home/mathieu/Pictures/SaveOurLake galleries/Gallery'), output)

print("Test stream subdirs")
with open('/tmp/out3.tar', 'wb') as output:
    stream_path_to_tar(pathlib.Path('/home/mathieu/Pictures/SaveOurLake galleries'), output)

