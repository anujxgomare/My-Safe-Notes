🔐 Secure Notes Management Application
📌 Overview

Secure Notes Management Application is a full-stack web application that allows users to securely create, store, update, and manage personal notes.
The application focuses on strong authentication, authorization, and data security while maintaining a clean and scalable architecture.

This project demonstrates real-world implementation of modern backend security concepts such as JWT, OAuth2, and Multi-Factor Authentication (MFA).

✨ Key Features

🔑 Secure user authentication using email and password

🌐 Social login using Google and GitHub (OAuth2)

🔐 Optional Multi-Factor Authentication (MFA) using Google Authenticator

👤 Role-based access control (Admin and User)

📝 Secure CRUD operations for personal notes

🧾 JWT-based stateless authentication for REST APIs

📊 Audit logging for note creation, update, and deletion

🛡️ Protected APIs using Spring Security filters

🛠️ Tech Stack
🔹 Backend

Java

Spring Boot

Spring Security

JWT

OAuth2

🔹 Frontend

React

REST API integration

🔹 Database

MySQL

🔹 Deployment

AWS (deployment in progress) ☁️

🏗️ Application Architecture

The application follows a layered architecture:

🎯 Controller Layer – Handles HTTP requests and responses

⚙️ Service Layer – Contains business logic

🗄️ Repository Layer – Manages database operations

This structure improves maintainability, scalability, and testability.

🔑 Authentication & Security Flow

👤 User logs in using email/password or OAuth (Google/GitHub)

🎫 On successful authentication, a JWT token is issued

🔐 The token is used to access secured REST APIs

📲 If MFA is enabled, an additional OTP verification step is required

✅ Access is granted based on user roles and permissions

🗃️ Database Design

🧑 Users, Roles, Notes, and Audit entities with proper relationships

🔗 Constraints and mappings ensure data integrity

🔒 Each user can access only their own notes

🚀 Deployment Status

✅ Application runs successfully in a local environment

☁️ AWS deployment (EC2, RDS, environment-based configuration) is in progress

🔗 Live deployment link will be added after final stabilization

🔮 Future Enhancements

☁️ Complete AWS production deployment

🔁 Add refresh token mechanism

🎨 Improve frontend UI and user experience

🤝 Add note sharing with controlled access

🔍 Implement search and tagging for notes

👨‍💻 Author

Anuj Gomare
