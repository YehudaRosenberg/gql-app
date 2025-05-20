import os
import logging

from graphene import Schema
from fastapi import FastAPI
from starlette_graphene3 import GraphQLApp, make_playground_handler
from app.db.database import prepare_database, Session as AppSession
from app.db.models import Employer, Job, JobApplication
from app.gql.queries import Query
from app.gql.mutations import Mutation
from app.middleware.depth_analysis import DepthAnalysisMiddleware

# Configure basic logging for main.py if you want to see APP_ENV status
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# --- Configuration for Depth Limits ---
APP_ENV = os.getenv("APP_ENV", "production").lower()

# Default depth limits
GENERAL_MAX_DEPTH = 5
MAX_ALIASES = 5
INTROSPECTION_QUERY_MAX_DEPTH = 15 # Default for introspection

if APP_ENV == "development":
    # Optionally override for development environment for easier debugging with UI
    # GENERAL_MAX_DEPTH = 10
    # INTROSPECTION_QUERY_MAX_DEPTH = 20
    log.info(
        f"Running in DEVELOPMENT mode. Applying depth limits: "
        f"General={GENERAL_MAX_DEPTH}, Introspection={INTROSPECTION_QUERY_MAX_DEPTH}, Aliases={MAX_ALIASES}"
    )
else:
    log.info(
        f"Running in PRODUCTION mode. Applying depth limits: "
        f"General={GENERAL_MAX_DEPTH}, Introspection={INTROSPECTION_QUERY_MAX_DEPTH}, Aliases={MAX_ALIASES}"
    )


# Create schema without middleware initially, as middleware is applied by GraphQLApp
schema = Schema(query=Query, mutation=Mutation)

# Create FastAPI app
app = FastAPI()

@app.on_event("startup")
def startup_event():
    prepare_database()

@app.get("/api/v1/system/readiness")
def readiness():
    return {"status": "ready"}

@app.get("/employers")
def get_employers_rest(): # Renamed to avoid potential GQL field name conflict
    session = AppSession()
    try:
        employers = session.query(Employer).all()
        return employers
    finally:
        session.close()

@app.get("/apps")
def get_applications_rest(): # Renamed
    with AppSession() as session: # Using context manager is good practice
        return session.query(JobApplication).count()

@app.get("/jobs")
def get_jobs_rest(): # Renamed
    with AppSession() as session:
        return session.query(Job).all()

# Mount GraphQLApp with middleware
app.mount(
    "/graphql", # Common practice to mount GraphQL on a specific path
    GraphQLApp(
        schema=schema,
        middleware=[
            DepthAnalysisMiddleware(
                max_depth=GENERAL_MAX_DEPTH,
                max_aliases=MAX_ALIASES,
                introspection_max_depth=INTROSPECTION_QUERY_MAX_DEPTH
            )
        ],
        on_get=make_playground_handler(), # For GET requests, show Playground
    ),
)