import setuptools
from setuptools import setup

setup(
    name='millegrilles_messages',
    version='2022.5.0',
    packages=setuptools.find_packages(),
    url='https://github.com/dugrema/millegrilles.messages.python',
    license='AFFERO',
    author='Mathieu Dugre',
    author_email='mathieu.dugre@mdugre.info',
    description='Scripts Python de messaging (MQ) pour MilleGrilles',
    install_requires=[
        'pika>=1.2.1,<2',
        'urllib3>=1.26.9',
        'requests>=2.27.1',
        'asyncio>=3.4.3,<4',
        'certifi>=2020.12.5',
        'certvalidator>=0.11.1',
        'cryptography>=37.0.2',
        'pycryptodome>=3.15.0,<4',
        'base58>=2.0.1',
        'py-multihash>=2.0.1',
        'py-multibase>=1.0.3',
        'pyopenssl>=21.0.0',
        'pynacl>=1.5.0',
        'pytz>=2020.4',
        'psutil>=5.8.0',
        'docker>=4.4.0',
        'redis>=4.3.1,<5'
    ]
)
