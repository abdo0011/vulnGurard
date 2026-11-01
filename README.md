VulnGuard – Vulnerability Management System

"Python" (https://img.shields.io/badge/Python-3.11-blue)
"Flask" (https://img.shields.io/badge/Flask-3.0-black)
"Database" (https://img.shields.io/badge/Database-SQLite-blue)
"Status" (https://img.shields.io/badge/Status-Development-orange)
"License" (https://img.shields.io/badge/License-MIT-green)

Overview

VulnGuard is a web-based Vulnerability Management System built with Python and Flask. It provides a centralized dashboard for managing vulnerabilities, tracking affected assets, and monitoring security risks.

The project aims to make vulnerability tracking and assessment easier through a simple and organized interface.

Screenshots

"VulnGuard Dashboard" (screenshots/dashboard.png)

Features

Vulnerability Management

- Add and manage vulnerability records.
- Track vulnerability severity and status.
- View vulnerability details.

Asset Management

- Organize and track affected assets.
- Associate vulnerabilities with assets.

Security Dashboard

- View vulnerability statistics.
- Monitor security status.
- Visualize vulnerability severity distribution.

Additional Features

- CSV import support.
- Dashboard charts.
- API endpoints for application data.

Tech Stack

- Backend: Python, Flask
- Frontend: HTML, CSS, JavaScript, Bootstrap
- Database: SQLite
- Charts: Chart.js

Project Structure

VulnGuard/
│
├── app.py
├── requirements.txt
├── README.md
├── screenshots/
│   └── dashboard.png
│
├── templates/
├── static/
└── database/

The actual folder structure may vary depending on the project version.

Installation

1. Clone the Repository

git clone https://github.com/abdo0011/vulnGurard.git

2. Navigate to the Project Directory

cd vulnGurard

3. Install Dependencies

pip install -r requirements.txt

4. Run the Application

python app.py

5. Open in Your Browser

http://127.0.0.1:5000

How It Works

1. Launch the VulnGuard web application.
2. Access the dashboard to review vulnerability statistics.
3. Add or import vulnerability records.
4. Manage assets and track associated vulnerabilities.
5. Monitor vulnerability severity and status through the dashboard.

Severity Classification

Severity| Description
Critical| Highest priority security risk
High| Significant security risk
Medium| Moderate security risk
Low| Lower-level security risk
Informational| Information that may require attention

Project Goals

- Simplify vulnerability tracking.
- Provide a centralized vulnerability management interface.
- Improve visibility into security risks.
- Support organized vulnerability assessment workflows.

Future Improvements

- User authentication and role management.
- Advanced filtering and search.
- Detailed vulnerability reports.
- More security assessment integrations.
- Improved dashboard analytics.


License

This project is licensed under the MIT License. See the "LICENSE" file for details.