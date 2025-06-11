from setuptools import setup, find_packages

setup(
    name='MemLib',
    version='1.7.0',
    packages=find_packages(),
    include_package_data=True,
    url='https://github.com/Zvendson/MemLib',
    license='MIT',
    author='Zvendson',
    author_email='',
    description='Library to interact with the Windows API and ctypes.',
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires='>=3.10',
    install_requires=[
        'psutil~=5.9.6',
        'pykeepass~=4.1.0',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: Microsoft :: Windows',
        'License :: OSI Approved :: MIT License',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
    ],
    keywords='windows api ctypes memory keepass',
)
