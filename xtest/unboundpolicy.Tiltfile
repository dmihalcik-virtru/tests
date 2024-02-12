# Tiltfile for development of OpenTDF backend
# reference https://docs.tilt.dev/api.html
# extensions https://github.com/tilt-dev/tilt-extensions

load(
    "../opentdf.Tiltfile",
    "opentdf_cluster_with_ingress",
)

opentdf_cluster_with_ingress(start_frontend=False)

local_resource(
    "outbound-test",
    "python3 sdk/py/test_unbound_policy.py",
    resource_deps=["backend",],
)