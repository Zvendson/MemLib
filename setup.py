from setuptools import setup



setup(
    name='MemLib',
    version='1.3.8',
    packages=['MemLib'],
    include_package_data=True,
    url='https://github.com/Zvendson/PyMemLib',
    license='',
    author='Zvendson',
    author_email='',
    description='Library to interact with the windows API and ctypes.',
    install_requires=[
        'psutil~=5.9.6',
    ]
)
