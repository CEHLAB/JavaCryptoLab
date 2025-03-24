# JavaCryptoLab
JavaCryptoLab – Librairie de cryptographie en JAVA

JavaCryptoLab est un projet Java exploitant Spring Boot pour exposer des fonctionnalités cryptographiques à travers deux interfaces : une API REST traditionnelle et une API GraphQL moderne. Le cœur du projet repose sur la classe `CryptoUtilImpl` qui centralise toutes les opérations cryptographiques essentielles.

## Objectif principal

La création du fichier `CryptoUtilImpl.java` constitue le cœur du projet, offrant une boîte à outils complète pour manipuler les données de manière sécurisée en Java. Ce fichier centralise les méthodes nécessaires pour :

- Génération de clés symétriques (AES) et asymétriques (RSA).
- Chiffrement et déchiffrement AES et RSA.
- Signature et vérification RSA.
- Signature HMAC pour assurer l'intégrité.
- Encodage et décodage Base64 et Hex.
- Gestion de certificats et clés via Java KeyStore (JKS).

## Fonctionnalités exposées via APIs

- **Chiffrement symétrique AES** : chiffrement/déchiffrement de données confidentielles.
- **Signature RSA** : signature numérique pour garantir l'authenticité.
- **Vérification RSA** : validation des signatures numériques.
- **HMAC** : vérification d'intégrité des données.

## Technologies utilisées

- Java & Spring Boot
- Spring Web (REST)
- Spring GraphQL
- Apache Commons Codec ...

## Structure du projet

```
src/main/java/org/chakir
├── CryptoApiApplication.java
├── controllers
│   └── CryptoRestController.java
├── dtos
│   ├── AesInput.java
│   ├── SignInput.java
│   └── VerifyInput.java
├── encryption
│   └── CryptoUtilImpl.java
└── graphql
    └── CryptoGraphQLResolver.java

src/main/resources/graphql
└── schema.graphqls
```

## Démarrer le projet

Exécutez la classe principale :

```bash
mvn spring-boot:run
```

## Tester les APIs

### REST API
- RSA Sign : `POST /api/crypto/rsa/sign`
- RSA Verify : `POST /api/crypto/rsa/verify`
- AES Encrypt : `POST /api/crypto/aes/encrypt`
- AES Decrypt : `POST /api/crypto/aes/decrypt`

### GraphQL API
Accédez à l'interface GraphiQL :

```
http://localhost:8080/graphql
```

Exemple de mutation GraphQL :
```graphql
mutation {
  aesEncrypt(input: { data: "Texte secret", secretKey: "1234567812345678" })
}
```




