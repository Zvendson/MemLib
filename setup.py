from setuptools import setup, find_packages

setup(
    name='MemLib',
    version='1.7.6',
    packages=find_packages(),
    include_package_data=True,
    url='https://github.com/Zvendson/MemLib',
    license='MIT',
    author='Zvendson',
    description='Windows-only Python toolkit for process memory access, binary scanning, and ctypes-based Win32 helpers.',
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires='>=3.10',
    install_requires=[
        'psutil~=5.9.6',
    ],
    extras_require={
        'keepass': ['pykeepass~=4.1.0'],
        'test': ['pytest>=8.0'],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Operating System :: Microsoft :: Windows',
        'License :: OSI Approved :: MIT License',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
    ],
    keywords='windows api ctypes memory keepass',
    project_urls={
        'Homepage': 'https://github.com/Zvendson/MemLib',
        'Repository': 'https://github.com/Zvendson/MemLib',
        'Issues': 'https://github.com/Zvendson/MemLib/issues',
    },
)
