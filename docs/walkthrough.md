# AegisLog Flow Visualizer - System Walkthrough

## Prerequisites
Before you begin, ensure you have the following installed on your system:
- **Python 3.8+** (for the backend)
- **Node.js 16+ & npm** (for the frontend)
- **PostgreSQL** (running and accessible)
- **Git** (optional, for version control)

---

## How to Run the Application

The application is split into a Python backend and a React frontend. Both need to be running for the application to function correctly.

### 1. Start the Backend Server

The backend requires Python and a PostgreSQL database.

1. Open a new terminal and navigate to the project root directory.
2. Ensure you have your `.env` file configured in the `backend/` directory with your PostgreSQL connection details.
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Navigate to the `backend` directory and start the FastAPI server:
   ```bash
   cd backend
   uvicorn app:app --host 127.0.0.1 --port 8000 --reload
   ```
   *The API will be available at `http://127.0.0.1:8000`.*

### 2. Start the Frontend Development Server

1. Open a second terminal and navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```
2. Install the Node.js dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   *The web interface will be available at `http://localhost:5173`.*

---

## Dependencies

### Backend Dependencies
The backend relies on the following major Python packages (found in `requirements.txt`):
- **FastAPI**: High-performance web framework for building the API.
- **Uvicorn**: ASGI server to run the FastAPI application.
- **SQLAlchemy**: ORM for database interactions.
- **psycopg2-binary**: PostgreSQL adapter for Python.
- **Pandas**: Used for robust data parsing and manipulation of uploaded CSV logs.
- **python-multipart**: Required for handling file uploads.
- **python-dotenv**: To load environment variables from the `.env` file.

### Frontend Dependencies
The frontend is built with React and uses the following major packages (found in `frontend/package.json`):
- **React & ReactDOM (^19.2.6)**: Core UI library.
- **React Router DOM**: For client-side routing.
- **Material-UI (@mui/material, @mui/icons-material)**: Comprehensive UI component library for premium designs.
- **Emotion**: Styling engine used by Material-UI.
- **Axios**: HTTP client for making API requests to the backend.
- **React Flow**: Node-based UI library (used for specialized diagramming if needed).
- **Vite**: Ultra-fast build tool and development server.

---

## How the System Works

AegisLog is a full-stack cybersecurity logging and correlation platform. It is designed to ingest raw network logs, correlate them against known threat signatures, and provide an interactive sequence diagram to visualize network flows.

### Architecture

1. **Frontend (React + Vite + Material UI)**
   - **Upload Page:** Allows users to upload raw log CSV files. It connects to the backend upload endpoint.
   - **Analysis Page:** Provides a rich, filtering interface. Users can visualize logs by different dimensions (IP Address, Username, Hostname, Protocol, Application). The core visualization is a custom-built sequence diagram that visually maps out network interactions (lines between communicating entities).

2. **Backend (FastAPI + SQLAlchemy + PostgreSQL)**
   - **Ingestion (`upload.py`):** Receives uploaded CSV files, cleans the data, and stores it in the PostgreSQL database.
   - **Correlation Engine (`correlation/`):** Runs algorithms on the ingested logs to detect patterns such as Brute Force attacks, Port Scans, and Data Exfiltration. It marks malicious logs with a `correlated` flag and assigns severity levels.
   - **Query Layer (`logs.py`):** Provides a robust API for the frontend to query logs. It handles filtering by time, severity, event category, and specific entities.

### Typical Workflow

1. **Upload Logs:** You start by uploading your network or system logs (`.csv`) via the Upload interface. The backend parses the logs, maps them to the database schema, and runs its correlation scripts to find threats.
2. **Setup Visualization:** Navigate to the Flow Analysis page. By default, the system will identify the most active endpoints in your dataset.
3. **Filter and Focus:** You can filter the data by:
   - **Visualize By:** Choose whether to map flows between IP Addresses, Usernames, or Protocols.
   - **Select/Type Entities:** Type specific IPs into the autocomplete box to isolate traffic involving only those endpoints. The layout mathematically forces the text box to take up the maximum width on its own dedicated row.
   - **Event Category & Severity:** Narrow down the logs to show only High Severity or Authentication-related events.
4. **Analyze:** The interactive sequence diagram visually represents network interactions over time. Malicious flows are highlighted in red (correlated events), making it easy to trace the origin and destination of an attack. Clicking on a flow opens a side drawer with detailed raw log data and mitigation playbook suggestions.

<img width="1918" height="906" alt="image" src="https://github.com/user-attachments/assets/c34ed20f-5a81-4296-86a3-889328a503ea" />