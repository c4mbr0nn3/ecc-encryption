# Asymmetric Encryption with N users access

Use Elliptic Curve Cryptography (ECC) for public/private key pairs to manage DEK (Data Encryption Key).

## Core concepts

### Key pairs

Each user (CEO, MDs, any other authorized individual or role) who needs to decrypt data will have their own ECC key
pair:

- **Private Key**: Kept absolutely secret and controlled by the user.
- **Public Key**: Shared openly with the system and used by others to encrypt data specifically for that user.

### User's secret role

The user secret, which the user inputs, will be used to protect their private key. This is typically done by:

- Generate EC key pair
- Encrypting the private key with a symmetric key derived from the user's secret (using PBKDF2 and a salt).
- Storing this encrypted private key with salt (ideally on hardware like yubikey). The system stores the public key,
  accessible for encryption operations.

### Data Encryption Key (DEK) encryption (wrapping)

When encrypted data record is created/updated a unique DEK is generated for its payload.

To grant access to the DEK to a user the system retrieves the user's public key. Then the DEK is encrypted with the
user's public key with hybrid encryption like **ECIES (Elliptic Curve Integrated Encryption Scheme)**.

ECIES essentially uses ECDH (Elliptic Curve Diffie-Hellman) to establish a shared secret with the public key, and this
shared secret is then used to symmetrically encrypt the DEK (using AES or similar).

The output of this process is the encrypted DEK, which can be stored alongside the encrypted data, and any necessary
ephemeral public key used in the encryption process.

### DEK decryption (unwrapping)

When a user needs to decrypt the data, they will:

1. Provide their secret to the system
2. The application uses the secret (and the stored salt) to derive a kay that decrypts the private key.
3. The application uses the decrypted private key to decrypt the DEK using ECIES.
4. The DEK is then used to decrypt the data payload using symmetric encryption (AES or similar).

## Database schema

### `users` table

| Column Name | Type | Constraint | Description                    |
|-------------|------|------------|--------------------------------|
| id          | int  | PK         | Unique identifier for the user |

### `user_key_credentials` table

| Column Name   | Type  | Constraint | Description                       |
|---------------|-------|------------|-----------------------------------|
| id            | int   | PK         | Unique identifier for the record  |
| user_id       | int   | FK         | Foreign key to the users table    |
| public_key    | bytea |            | User's public key                 |
| private_key   | bytea |            | Encrypted user's private key      |
| salt          | bytea |            | Salt used for key derivation      |
| key_algorithm | text  |            | Algorithm used for key generation |

### `encypted_data` table

| Column Name | Type  | Constraint | Description                      |
|-------------|-------|------------|----------------------------------|
| id          | int   | PK         | Unique identifier for the record |
| data        | bytea |            | Encrypted data payload           |

### `encrypted_data_access_grants` table

| Column Name       | Type  | Constraint | Description                                                                                                                                                    |
|-------------------|-------|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id                | int   | PK         | Unique identifier for the record                                                                                                                               |
| user_id           | int   | FK         | Foreign key to the users table                                                                                                                                 |
| encrypted_data_id | int   | FK         | Foreign key to the encrypted data table                                                                                                                        |
| encrypted_dek     | bytea |            | The DEK encrypted with the users's public key. <br/>This is the output of a scheme like ECIES, containing ephemeral public key, ciphertext of DEK, and MAC tag |







