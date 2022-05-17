from setuptools import setup
import subprocess


# def get_version():
#     try:
#         with open('version.txt', 'r') as version_file:
#             version = version_file.readline().strip()
#     except FileNotFoundError as e:
#         with open('build.txt', "r") as buildno_file:
#             build_no = buildno_file.read().strip()
#
#         commande_git_version = ['git', 'name-rev', '--name-only', 'HEAD']
#         output_process = subprocess.run(commande_git_version, stdout=subprocess.PIPE)
#         version = output_process.stdout.decode('utf8').strip()
#         version = '%s.%s' % (version, build_no)
#         print("Version: %s" % (version))
#
#     return version


setup(
    name='millegrilles.messages',
    # version='%s' % get_version(),
    version='2022.3.0',
    packages=['millegrilles.messages'],
    url='https://github.com/dugrema/millegrilles.messages.python',
    license='AFFERO',
    author='Mathieu Dugre',
    author_email='mathieu.dugre@mdugre.info',
    description='Scripts Python de messaging (MQ) pour MilleGrilles',
    install_requires=[
        'pika>=1.2.1,<2',
        'urllib3>=1.26.9',
        'requests>=2.27.1',
        'certifi>=2020.12.5',
        'certvalidator>=0.11.1',
        'cryptography>=37.0.2',
        'base58>=2.0.1',
        'py-cid',
        'py-multihash>=0.8.2',
        'py-multibase>=1.0.3',
        'pyopenssl>=21.0.0',
        'pynacl>=1.5.0',
        'pytz>=2020.4',
        'psutil>=5.8.0',
        'docker>=4.4.0',
    ]
)
