# Authentification & Gestion d’Articles avec FastAPI

Ce projet propose une API REST pour gérer l’authentification des utilisateurs et la gestion d’articles, basée sur **FastAPI**, **SQLModel** et **JWT**.

## Fonctionnalités

- **Inscription et connexion** des utilisateurs avec mot de passe hashé
- **Authentification JWT**
- **Réinitialisation du mot de passe** (forgot/reset password)
- **Création d’articles** liés à un utilisateur
- **Récupération de tous les articles**
- **Récupération des articles d’un utilisateur**
- **Récupération d’un article par ID**

## Installation

1. **Cloner le dépôt**
   ```bash
   git clone https://github.com/tgede46/authentification.git
   cd authentification/jwt
   ```

2. **Créer un environnement virtuel et installer les dépendances**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Lancer le serveur**
   ```bash
   uvicorn main:app --reload
   ```

## Utilisation de l’API

- Documentation interactive : [http://localhost:8000/docs](http://localhost:8000/docs)

### Endpoints principaux

| Méthode | Endpoint                  | Description                                 |
|---------|---------------------------|---------------------------------------------|
| POST    | `/register`               | Inscription utilisateur                     |
| POST    | `/login`                  | Connexion utilisateur (JWT)                 |
| POST    | `/forgot-password`        | Demander la réinitialisation du mot de passe|
| POST    | `/reset-password`         | Réinitialiser le mot de passe               |
| POST    | `/` (articles)            | Créer un article                            |
| GET     | `/` (articles)            | Récupérer tous les articles                 |
| GET     | `/user/{username}`        | Articles d’un utilisateur                   |
| GET     | `/{article_id}`           | Article par ID                              |

## Structure du projet

```
.
├── main.py
├── models.py
├── auth.py
├── database.py
├── requirements.txt
└── jwt.db
```

## Auteurs

- [tgede46](https://github.com/tgede46)

---

**N’hésite pas à adapter ce README selon tes