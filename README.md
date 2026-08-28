# Vulnerability Tracking and Remediation System

## Team Members

| S.No | University ID | Name |
|---|---|---|
| 1 | 2420030158 | MODALLA PRANITH REDDY |
| 2 | 2420030636 | V Praneeth |
| 3 | 2420030351 | Y Karthikeya |

## Supervisor

**Venkateswari Ketineni**

## Abstract

The Vulnerability Tracking and Remediation System is a security management platform designed to help organizations identify, track, prioritize, and resolve security vulnerabilities in their applications and systems. The system provides a centralized platform where security analysts can report vulnerabilities, classify them based on severity, assign remediation tasks to developers, and monitor their progress until the issues are resolved and verified.

The system implements role-based access control for administrators, security analysts, and developers. It maintains the complete lifecycle of each vulnerability, including reporting, assignment, remediation, verification, and closure. Notifications can be generated for new assignments, status changes, and approaching deadlines, while audit logs maintain a record of important user and system activities. A dashboard provides an overview of open, critical, resolved, and closed vulnerabilities through reports and visual analytics.

## Technologies

- Java
- Spring Boot
- Spring Cloud
- Eureka
- Spring Cloud Gateway
- Spring Security
- JWT
- MySQL
- RabbitMQ
- React
- Prometheus
- ELK Stack
- Docker
- Kubernetes
- GitHub Actions
- Postman

## Architecture

The project follows a microservices-based architecture with separate services for:

- Authentication
- User Management
- Vulnerability Tracking
- Remediation
- Notification
- Auditing

REST APIs are used for communication between services.

## Setup and Execution

### Prerequisites

- JDK 21
- Maven
- Node.js
- npm
- Docker Desktop
- Git

### Backend

Backend services are located inside:

`src/backend/`

### Frontend

The React application is located inside:

`src/frontend/vulnerability-dashboard/`

### Infrastructure

Docker, Kubernetes, Prometheus and ELK configurations are maintained inside:

`infrastructure/`

## Project Status

### Current Phase

**Phase 1 – Core Infrastructure Setup**

### Status

🚧 In Progress

### Completed

- Repository structure
- Project documentation structure
- Initial architecture planning

### In Progress

- Eureka Server
- API Gateway
- Authentication Service

### Upcoming

- User Service
- Vulnerability Service
- Remediation Service
- RabbitMQ integration
- Notification Service
- Audit Service
- React Dashboard
- Monitoring
- Docker
- Kubernetes
- CI/CD

## Project Objectives

- Implement role-based access control.
- Track the complete vulnerability lifecycle.
- Classify vulnerabilities based on severity.
- Assign remediation tasks to developers.
- Provide automated notifications.
- Maintain audit logs.
- Provide dashboard-based visual analytics.
- Build the platform using microservices.

## License

This project is developed as part of the SOA Programming and Microservices course.