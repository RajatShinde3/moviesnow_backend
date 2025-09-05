from fastapi import FastAPI
from fastapi.testclient import TestClient
import importlib, os

mod = importlib.import_module('app.api.v1.routers.user.me')

async def _no_rate_limit(*_, **__):
    return None
mod.rate_limit = _no_rate_limit

class FakeUserRepo:
    def __init__(self):
        self.calls=0
        self.last_user_id=None
        self.last_tid=None
    def add_favorite(self, user_id, title_id):
        self.calls +=1
        self.last_user_id, self.last_tid = user_id, title_id

repo = FakeUserRepo()
mod.get_user_repository = lambda: repo

async def _fake_current_user(*args, **kwargs):
    return {"id": "u-123", "email": "user@example.com"}
mod.get_current_user = _fake_current_user
mod.sanitize_title_id = lambda x: x

os.environ.pop('PUBLIC_API_KEY', None)
os.environ.pop('PUBLIC_API_KEY_SHA256', None)

app = FastAPI()
app.include_router(mod.router, prefix='/api/v1')
client = TestClient(app)
r = client.post('/api/v1/favorites/tt123')
print('status', r.status_code)
print('headers', dict(r.headers))
print('text', r.text)
