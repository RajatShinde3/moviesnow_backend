import importlib, inspect
from fastapi import FastAPI

mod = importlib.import_module('app.api.v1.routers.admin.staff')
app = FastAPI()
app.include_router(mod.router, prefix='/api/v1/admin')

for route in app.routes:
    methods = getattr(route,'methods', None)
    path = getattr(route,'path', None)
    if path=='/api/v1/admin/staff/superusers' and methods and 'GET' in methods:
        print('has get_request_handler:', hasattr(route,'get_request_handler'))
        grh = getattr(route,'get_route_handler')
        print('has get_route_handler:', bool(grh))
        handler = route.get_route_handler()
        print('handler obj:', handler)
        try:
            sig = inspect.signature(handler)
            print('handler sig params:', list(sig.parameters.keys()))
        except Exception as e:
            print('handler sig error:', e)