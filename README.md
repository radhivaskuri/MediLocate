# MediLocate 💊

**MediLocate** is a web-based medicine and pharmacy management application designed to help users find medicines, check availability, and manage medicine-related reservations.

## Features

- User Registration and Login
- Medicine Search and Availability
- Pharmacy and Medicine Management
- Medicine Reservations
- User and Role Management

## Tech Stack

- **Backend:** Python, Flask
- **Database:** MySQL
- **Frontend:** HTML, CSS, JavaScript
- **Deployment:** Railway
- **Version Control:** Git and GitHub

## Live Demo

[Visit MediLocate](https://medilocate-production.up.railway.app)

## Installation and Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/radhivaskuri/MediLocate.git
   ```

2. Navigate to the project folder:

   ```bash
   cd MediLocate
   ```

3. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   ```

   Windows PowerShell:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Configure the required environment variables in a `.env` file, including the database connection details and secret key.

6. Ensure the MySQL database and required tables are configured.

7. Start the application:

   ```bash
   python app.py
   ```

## Purpose

MediLocate aims to make medicine availability and pharmacy-related operations easier through a centralized web application.

## Future Enhancements

- Advanced medicine search and filtering
- Improved pharmacy information
- Enhanced reservation tracking
- Better user experience and accessibility
