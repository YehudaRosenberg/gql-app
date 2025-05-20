# main.py
import os
import logging

from graphene import Schema
from fastapi import FastAPI
from fastapi.responses import RedirectResponse # Import RedirectResponse
from starlette_graphene3 import GraphQLApp, make_playground_handler
from app.db.database import prepare_database, Session as AppSession
from app.db.models import Employer, Job, JobApplication
from app.gql.queries import Query
from app.gql.mutations import Mutation
from app.middleware.depth_analysis import DepthAnalysisMiddleware

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# --- Configuration for Depth Limits ---
APP_ENV = os.getenv("APP_ENV", "production").lower()

GENERAL_MAX_DEPTH = 5
MAX_ALIASES = 5
INTROSPECTION_QUERY_MAX_DEPTH = 15

if APP_ENV == "development":
    log.info(
        f"Running in DEVELOPMENT mode. Applying depth limits: "
        f"General={GENERAL_MAX_DEPTH}, Introspection={INTROSPECTION_QUERY_MAX_DEPTH}, Aliases={MAX_ALIASES}"
    )
else:
    log.info(
        f"Running in PRODUCTION mode. Applying depth limits: "
        f"General={GENERAL_MAX_DEPTH}, Introspection={INTROSPECTION_QUERY_MAX_DEPTH}, Aliases={MAX_ALIASES}"
    )

schema = Schema(query=Query, mutation=Mutation)
app = FastAPI()

@app.on_event("startup")
def startup_event():
    prepare_database()

# --- Redirect from / to /graphql ---
@app.get("/", include_in_schema=False) # include_in_schema=False to hide from OpenAPI docs
async def redirect_to_graphql():
    """
    Redirects the root path to the GraphQL Playground.
    """
    return RedirectResponse(url="/graphql", status_code=307) # 307 for Temporary Redirect

# --- REST endpoints ---
@app.get("/api/v1/system/readiness")
def readiness():
    return {"status": "ready"}

@app.get("/employers")
def get_employers_rest():
    session = AppSession()
    try:
        employers = session.query(Employer).all()
        return employers
    finally:
        session.close()

@app.get("/apps")
def get_applications_rest():
    with AppSession() as session:
        return session.query(JobApplication).count()

@app.get("/jobs")
def get_jobs_rest():
    with AppSession() as session:
        return session.query(Job).all()

# --- Mount GraphQLApp with middleware ---
app.mount(
    "/graphql",
    GraphQLApp(
        schema=schema,
        middleware=[
            DepthAnalysisMiddleware(
                max_depth=GENERAL_MAX_DEPTH,
                max_aliases=MAX_ALIASES,
                introspection_max_depth=INTROSPECTION_QUERY_MAX_DEPTH
            )
        ],
        on_get=make_playground_handler(),
    ),
)