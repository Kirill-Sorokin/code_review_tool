# Code Review Tool

A web application for reviewing code, adding comments, and highlighting multiple lines of code. Built with Go for the backend and vanilla HTML, CSS, and JavaScript for the frontend.

## Features

- User authentication (sign up and login)
- Upload and display code files
- Add comments to specific lines or ranges of lines in the code
- Highlight commented lines
- Search and filter comments
- Ensure no overlapping comments
- Timestamp for comments

## Prerequisites

- Go (Golang) installed
- Git installed

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Kirill-Sorokin/code_review_tool.git
   cd code_review_tool

2. Run the backend server:
   ```sh
   go run main.go

3. Open the 'index.html' file in a web browser.

**Usage**
- Sign up for a new account or log in with an existing account.
- Upload a code file for review.
- View the code and add comments by specifying the line numbers.
- Comments will be highlighted in the code, and you can see all comments in the comments section.
