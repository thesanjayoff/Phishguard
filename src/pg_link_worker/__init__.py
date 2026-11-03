"""Link sandbox worker. Runs ONLY inside the link container image (see docker/linkbox).

It is the only component that ever connects to a suspicious URL. Everything it prints is untrusted
data to the host, which schema-checks and length-caps it before use."""
__version__ = "0.1"
