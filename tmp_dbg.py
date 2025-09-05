import importlib, inspect
from fastapi import FastAPI
from starlette.routing import request_response

mod = importlib.import_module('app.api.v1.routers.admin.staff')
app = FastAPI()
app.include_router(mod.router, prefix='/api/v1/admin')
print('routes count', len(app.routes))
for route in app.routes:
    methods = getattr(route,'methods', None)
    path = getattr(route,'path', None)
    if path and methods:
        print('route:', path, methods)
        if path=='/api/v1/admin/staff/superusers' and 'GET' in methods:
            print('found route')
            print('endpoint pre:', route.endpoint)
            print('has get_request_handler:', hasattr(route,'get_request_handler'))
            if hasattr(route, 'get_request_handler'):
                handler = route.get_request_handler()
                print('get_request_handler returned:', handler)
                try:
                    sig = inspect.signature(handler)
                    print('handler sig param count:', len(sig.parameters))
                except Exception as e:
                    print('sig err', e)
                # Wrap if needed
                if len(getattr(inspect.signature(handler),'parameters',{}))==1:
                    route.app = request_response(handler)
                    print('wrapped to ASGI via request_response')
                else:
                    route.app = handler
            else:
                route.app = route.get_route_handler()
            print('route.app is now:', route.app)