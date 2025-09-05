import importlib
from fastapi import FastAPI
from inspect import signature
from starlette.routing import request_response

mod = importlib.import_module('app.api.v1.routers.admin.staff')
app = FastAPI()
app.include_router(mod.router, prefix='/api/v1/admin')

for route in app.routes:
    if getattr(route, 'path', None) == '/api/v1/admin/staff/superusers' and 'GET' in getattr(route, 'methods', set()):
        print('route class:', type(route))
        print('has get_request_handler?', hasattr(route, 'get_request_handler'))
        if hasattr(route, 'get_request_handler'):
            grh = route.get_request_handler()
            print('get_request_handler returned:', grh)
            try:
                print('sig of grh:', signature(grh))
            except Exception as e:
                print('sig error for grh:', e)
        if hasattr(route, 'get_route_handler'):
            grh2 = route.get_route_handler()
            print('get_route_handler returned:', grh2)
            try:
                print('sig of grh2:', signature(grh2))
            except Exception as e:
                print('sig error for grh2:', e)
        fn = route.endpoint
        print('endpoint:', fn)
        depth=0
        while hasattr(fn, '__wrapped__') and depth<10:
            fn = fn.__wrapped__
            depth+=1
        print('unwrapped endpoint:', fn)
        try:
            print('sig endpoint:', signature(fn))
        except Exception as e:
            print('sig error for endpoint:', e)
        if hasattr(route, 'get_request_handler'):
            wrapped = request_response(route.get_request_handler())
            print('wrapped via request_response:', wrapped)
            try:
                print('sig wrapped:', signature(wrapped))
            except Exception as e:
                print('sig error for wrapped:', e)