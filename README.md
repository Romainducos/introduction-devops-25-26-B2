# introduction-devops-25-26-B2

Découverte des github actions

## Hello World ViteJS Project

Ce projet est une application Hello World créée avec ViteJS.

### Prérequis

- Node.js 20 ou supérieur
- npm

### Installation

```bash
npm install
```

### Scripts disponibles

- `npm run dev` - Lance le serveur de développement
- `npm run build` - Compile l'application pour la production
- `npm run preview` - Prévisualise la version de production
- `npm run lint` - Vérifie le code avec ESLint
- `npm run format` - Formate le code avec Prettier
- `npm run format:check` - Vérifie le formatage du code

### CI/CD Pipeline

Le pipeline CI inclut :

1. **Lint** - Vérification du code avec ESLint
2. **Format** - Vérification du formatage avec Prettier
3. **Snyk** - Analyse de sécurité des dépendances
4. **Build** - Compilation de l'application ViteJS
