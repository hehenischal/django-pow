from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="django-pow",
    version="0.1.0",
    description="Proof of Work protection for Django views — stops bots and rate-limit abuse at the client level.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/yourname/django-pow",
    license="MIT",
    packages=find_packages(exclude=["tests*", "examples*", "docs*"]),
    include_package_data=True,
    package_data={
        "django_pow": [
            "static/django_pow/*.js",
            "templates/django_pow/*.html",
        ]
    },
    python_requires=">=3.10",
    install_requires=[
        "Django>=4.0",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-django",
            "black",
            "isort",
        ]
    },
    classifiers=[
        "Framework :: Django",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.0",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
    ],
    keywords=["django", "proof-of-work", "bot-protection", "rate-limiting", "security"],
)
