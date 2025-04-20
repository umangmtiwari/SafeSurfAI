import pkg_resources

def extract_versions():
    libraries = [
        'Flask',
        'Werkzeug',
        'requests',
        'beautifulsoup4',
        'scikit-learn',
        'pandas',
        'joblib'
    ]
    
    versions = {}
    for lib in libraries:
        try:
            version = pkg_resources.get_distribution(lib).version
            versions[lib] = f"{lib}=={version}"
        except pkg_resources.DistributionNotFound:
            versions[lib] = f"{lib} not installed"
    
    return versions

if __name__ == "__main__":
    versions = extract_versions()
    for lib, version in versions.items():
        print(version)
