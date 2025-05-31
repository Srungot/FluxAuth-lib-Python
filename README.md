# FluxAuth Python Library

## English

### Description
FluxAuth is a Python library for license management and application security. It provides robust authentication, hardware ID (HWID) binding, and various security features to protect your applications.

### Features
- License authentication with HWID binding
- Anti-debug protection
- Virtual machine detection
- Process blacklisting
- Time tampering detection
- File integrity checking
- Qt applications protection
- Variable management
- Webhook integration

### Installation & Setup
1. Download the `flux.py` file
2. Place it in the same directory as your main Python file
3. Import and use it in your code

### Basic Usage
```python
from flux import Flux

auth = Flux(
    application_id="your_app_id",
    secret_key="your_secret_key",
    name_app="YourApp",
    version_app="1.0"
)

try:
    auth.authenticate("your_license_key")
    print("Authentication successful!")
except Exception as e:
    print(f"Authentication failed: {e}")
```

### Security Features
- Anti-debugging mechanisms
- Protection against reverse engineering
- Blacklisted process detection
- Virtual machine detection
- System time manipulation detection
- File integrity verification

### Advanced Features
- Variable management system
- Webhook integration for notifications
- License time tracking
- HWID management
- Qt applications protection

---

## Français

### Description
FluxAuth est une bibliothèque Python pour la gestion des licences et la sécurité des applications. Elle fournit une authentification robuste, une liaison à l'identifiant matériel (HWID) et diverses fonctionnalités de sécurité pour protéger vos applications.

### Fonctionnalités
- Authentification des licences avec liaison HWID
- Protection anti-débogage
- Détection des machines virtuelles
- Liste noire des processus
- Détection de manipulation du temps
- Vérification de l'intégrité des fichiers
- Protection des applications Qt
- Gestion des variables
- Intégration de webhooks

### Installation & Configuration
1. Téléchargez le fichier `flux.py`
2. Placez-le dans le même répertoire que votre fichier Python principal
3. Importez et utilisez-le dans votre code

### Utilisation de Base
```python
from flux import Flux

auth = Flux(
    application_id="votre_app_id",
    secret_key="votre_cle_secrete",
    name_app="VotreApp",
    version_app="1.0"
)

try:
    auth.authenticate("votre_cle_licence")
    print("Authentification réussie !")
except Exception as e:
    print(f"Échec de l'authentification : {e}")
```

### Fonctionnalités de Sécurité
- Mécanismes anti-débogage
- Protection contre l'ingénierie inverse
- Détection des processus blacklistés
- Détection des machines virtuelles
- Détection de manipulation du temps système
- Vérification de l'intégrité des fichiers

### Fonctionnalités Avancées
- Système de gestion des variables
- Intégration de webhooks pour les notifications
- Suivi des temps de licence
- Gestion des HWID
- Protection des applications Qt

