from setuptools import find_packages, setup



setup(
    name='MemLib',
    version='1.0.0',
    packages=find_packages(where="MemLib"),
    include_package_data=True,
    package_dir={"": "MemLib"},
    url='https://github.com/Zvendson/PyMemLib',
    license='',
    author='Zvendson',
    author_email='',
    description='Library to interact with the windows API and ctypes.',
)
