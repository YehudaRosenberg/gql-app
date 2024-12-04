from graphene import Schema
from fastapi import FastAPI
from starlette_graphene3 import GraphQLApp, make_playground_handler
from app.db.database import prepare_database, Session
from app.db.models import Employer, Job
from app.gql.queries import Query
from app.gql.mutations import Mutation
from contextlib import asynccontextmanager

schema = Schema(query=Query, mutation=Mutation)

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


@app.get("/jobs")
def get_jobs():
    with Session() as session:
        return session.query(Job).all()


app.mount("/", GraphQLApp(
    schema=schema,
    on_get=make_playground_handler()
))
