# Building a Secure GraphQL API

This project is based on the material of the course [*Building GraphQL APIs with Python: Beginner To Pro*](https://www.udemy.com/course/building-graphql-apis-with-python). Except the password hashing and authentication mechanism implemented in the loginUser API, all the security checks were made by me as part of a self learning journey aiming to fortify my security knowledge on GraphQL APIs.
This app serves as a practical demonstration and learning exercise focused on **building a secure GraphQL API**. We explore common security considerations and implement robust solutions using a modern Python stack.

Whether you're a GraphQL developer looking to harden your APIs or a security engineer exploring best practices in this space, this codebase provides concrete examples.

**Core Technologies:**

* **Python**
* **FastAPI:** For the high-performance web framework foundation.
* **Graphene:** For implementing the GraphQL schema and logic.
* **SQLAlchemy:** For database interaction (ORM).
* **JWT (PyJWT):** For stateless authentication.
* **Argon2:** For strong password hashing.

## Security Focus

Security wasn't an afterthought here. Throughout the development reflected in this repository, we've focused on implementing:

* **Robust Authentication:** Secure JWT handling with expiration.
* **Granular Authorization:** Role-based (`admin`/`user`) and ownership-based access control.
* **Secure Password Handling:** Strong hashing (Argon2) and strong password policies (complexity, breach checks via `pwnedpasswords`, checks against user info).
* **Input Validation:** Validating critical inputs like email formats (`email-validator`) and passwords.
* **Secure Error Handling:** Preventing information disclosure through generic client-facing errors while logging details server-side.
* **Hardened API Endpoints:** Ensuring all data-modifying operations and sensitive queries require appropriate authentication and authorization.
* **GraphQL Specific Defenses:** Query depth and alias limiting middleware.

\* Although some security tools flag it as a security issue, the introspection is enabled by design as it does not expose any internal API or sensitive data and in the same time improves significantly the user experience to understand all the available APIs.

This project aims to show *how* these pieces fit together in a functional API.

## Reporting Vulnerabilites
Did you find any vulnerability in this project? I would be more than happy to know about it! Please send me your findings via the Private vulnerability reporting. To do so, please see the `SECURITY.md` file.

## Running Locally: Step-by-Step Guide

Want to explore the API yourself? Here’s how to get it running locally:

**Prerequisites:**

* Python 3.8+ and Pip
* Git
* A running PostgreSQL database (or modify `DB_URL` for a different SQLAlchemy-compatible DB like SQLite).

**Steps:**

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/YehudaRosenberg/gql-app
    cd gql-app-main 
    ```

2.  **Create & Activate Virtual Environment (Recommended):**
    ```bash
    # Create venv
    python -m venv venv
    # Activate venv
    # Linux/macOS:
    source venv/bin/activate
    # Windows (cmd/powershell):
    # .\venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    * Create a `.env` file in the project root directory (where `main.py` is).
    * Populate the `.env` file with the following required variables:

        ```dotenv
        # --- Database ---
        # Example for PostgreSQL:
        DB_URL=postgresql+psycopg2://YOUR_DB_USER:YOUR_DB_PASSWORD@localhost:5432/your_gql_job_db_name
        # Example for SQLite (creates file 'local_gql_app.db' in the root):
        # DB_URL=sqlite+pysqlite:///./local_gql_app.db

        # --- JWT Settings ---
        # Generate a strong, random secret key (e.g., using openssl rand -hex 32)
        SECRET_KEY=your_super_secret_random_key_here
        ALGORITHM=HS256 # Or another supported algorithm if preferred
        TOKEN_EXPIRATION_TIME_MINUTES=30 # Or your desired token lifetime

        # --- Other potential config ---
        # Add any other environment-specific settings if needed
        ```
    * **Important:** Ensure the database specified in `DB_URL` exists and is accessible with the provided credentials. For PostgreSQL, you may need to create the database first. The application will create the necessary tables on startup if they don't exist.

5.  **Run the Application:**
    ```bash
    uvicorn main:app --reload --port 8000
    ```
    * `--reload` enables auto-reloading on code changes (great for development).
    * `--port 8000` specifies the port (change if needed).

6.  **Access the API:**
    * Open your web browser and navigate to `http://127.0.0.1:8000/`.
    * You should see the GraphQL Playground interface, which allows you to interactively explore and run queries/mutations.

7.  **Using the API:**
    * Use the `loginUser` mutation (see below) in the Playground to get an authentication token.
    * For operations requiring authentication, open the "HTTP HEADERS" panel at the bottom left of the Playground and add:
        ```json
        {
          "Authorization": "Bearer <YOUR_JWT_TOKEN>"
        }
        ```
      (Replace `<YOUR_JWT_TOKEN>` with the actual token obtained from login).

## API Endpoint

* **GraphQL Endpoint:** `/` (Accepts POST requests for queries/mutations, GET for Playground)

## Authentication

* **Method:** JWT Bearer Token
* **Obtain Token:** Use `loginUser` mutation.
* **Usage:** Include `Authorization: Bearer <TOKEN>` header in requests for protected operations.

## GraphQL Schema Reference

### Queries

*(AuthN = Authentication Required, AuthZ = Authorization Required)*

* **`me: UserObject`**
    * Retrieves the profile of the currently authenticated user.
    * **AuthN:** Yes | **AuthZ:** Any Authenticated User


* **`jobs: [JobObject]`**
    * Retrieves a list of all job postings.
    * **AuthN:** Yes | **AuthZ:** Any Authenticated User


* **`job(id: Int!): JobObject`**
    * Retrieves a specific job by ID.
    * **AuthN:** Yes | **AuthZ:** Any Authenticated User


* **`employers: [EmployerObject]`**
    * Retrieves a list of all employers.
    * **AuthN:** Yes | **AuthZ:** Any Authenticated User


* **`employer(id: Int!): EmployerObject`**
    * Retrieves a specific employer by ID.
    * **AuthN:** Yes | **AuthZ:** Any Authenticated User


* **`jobApplications: [JobApplicationObject]`**
    * Retrieves job applications (filtered by role).
    * **AuthN:** Yes | **AuthZ:** User (Own data) / Admin (All data)


* **`users: [UserObject]`**
    * Retrieves a list of all users.
    * **AuthN:** Yes | **AuthZ:** Admin Only

### Mutations

* **`loginUser(email: String!, password: String!): LoginUserPayload`** (Payload: `{token: String}`)
    * Authenticates a user, returns JWT.
    * **AuthN:** No | **AuthZ:** Public


* **`addUser(username: String!, email: String!, password: String!, role: String!)`**: `UserObject`
    * Creates a new user. Enforces password policy.
    * **AuthN:** No (for `role='user'`) / Yes (for `role='admin'`)
    * **AuthZ:** Public (for `role='user'`) / Admin Only (for `role='admin'`)


* **`updateUser(username: String, email: String, password: String, currentPassword: String): UserObject`**
    * Updates authenticated user's profile. Requires `currentPassword` to change `password`. Enforces password policy. Validates email.
    * **AuthN:** Yes | **AuthZ:** Self Only


* **`deleteUser(userId: Int!): DeleteUserPayload`** (Payload: `{success: Boolean}`)
    * Deletes a user account. Prevents deletion of the last admin.
    * **AuthN:** Yes | **AuthZ:** Self or Admin


* **`applyToJob(jobId: Int!): JobApplicationObject`**
    * Applies the authenticated user to a specific job.
    * **AuthN:** Yes | **AuthZ:** Self Only


* **`addJob(title: String!, description: String!, employerId: Int!): JobObject`**
    * Creates a new job posting.
    * **AuthN:** Yes | **AuthZ:** Admin Only


* **`updateJob(jobId: Int!, title: String, description: String, employerId: Int): JobObject`**
    * Updates an existing job posting.
    * **AuthN:** Yes | **AuthZ:** Admin Only


* **`deleteJob(id: Int!): DeleteJobPayload`** (Payload: `{success: Boolean}`)
    * Deletes a job posting.
    * **AuthN:** Yes | **AuthZ:** Admin Only


* **`addEmployer(name: String!, contactEmail: String!, industry: String!): EmployerObject`**
    * Creates a new employer profile. Validates contact email.
    * **AuthN:** Yes | **AuthZ:** Admin Only


* **`updateEmployer(employerId: Int!, name: String, contactEmail: String, industry: String): EmployerObject`**
    * Updates an existing employer profile. Validates contact email if changed.
    * **AuthN:** Yes | **AuthZ:** Admin Only


* **`deleteEmployer(id: Int!): DeleteEmployerPayload`** (Payload: `{success: Boolean}`)
    * Deletes an employer profile. Fails if employer has associated jobs.
    * **AuthN:** Yes | **AuthZ:** Admin Only