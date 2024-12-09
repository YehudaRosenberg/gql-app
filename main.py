from graphene import Schema
from fastapi import FastAPI
from starlette_graphene3 import GraphQLApp, make_playground_handler
from app.db.database import prepare_database, Session
from app.db.models import Employer, Job, JobApplication
from app.gql.queries import Query
from app.gql.mutations import Mutation
from app.middleware.depth_analysis import DepthAnalysisMiddleware

# Create schema without middleware
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
def get_employers():
    session = Session()
    employers = session.query(Employer).all()
    session.close()
    return employers

@app.get("/apps")
def get_applications():
    with Session() as session:
        return session.query(JobApplication).count()

@app.get("/jobs")
def get_jobs():
    with Session() as session:
        return session.query(Job).all()

# Mount GraphQLApp with middleware
app.mount(
    "/",
    GraphQLApp(
        schema=schema,
        middleware=[DepthAnalysisMiddleware(max_depth=5)],  # Apply middleware here
        on_get=make_playground_handler(),
    ),
)
