# Lockbox

**Coffre-fort de mots de passe en ligne de commande, basé sur Argon2id et AES-256-GCM, avec chiffrement en enveloppe, en-tête authentifié et audit de la santé des mots de passe.**

*[English version](README.md)*

## Fonctionnement du chiffrement

```
 mot de passe maître ──► Argon2id (sel aléatoire, 64 Mo, 3 passes) ──► KEK   jamais stockée
 DEK aléatoire de 256 bits ──── AES-256-GCM(KEK) ────► DEK chiffrée  ┐
 entrées (JSON) ─────────────── AES-256-GCM(DEK) ────► chiffré       ├─ vault.json
 en-tête {format, version, paramètres KDF, sel} ── authentifié ──────┘
```

| Choix | Raison |
|---|---|
| **Argon2id** pour dériver la clé | Fonction « memory-hard » : chaque essai du mot de passe maître coûte 64 Mo de RAM et environ 130 ms, ce qui rend le cassage par GPU coûteux. Recommandé par l'OWASP. |
| **Chiffrement en enveloppe** (la KEK protège une DEK aléatoire) | Changer le mot de passe maître ne rechiffre que 32 octets. La clé de données ne dépend pas de la qualité du mot de passe. `lockbox passwd --rotate-key` remplace aussi la DEK. C'est le même principe que 1Password, Bitwarden ou LUKS. |
| **AES-256-GCM** | Chiffrement authentifié : le moindre octet modifié fait échouer le déchiffrement. |
| **Nonce aléatoire neuf à chaque sauvegarde** | Un nonce GCM ne doit jamais être réutilisé avec la même clé. Un test le vérifie. |
| **En-tête en données associées** | Un attaquant qui abaisse le coût d'Argon2 dans le fichier, ou qui échange le sel ou le bloc de données, rend le déchiffrement impossible. Les trois cas sont testés. |
| **Écriture atomique, permissions `0600`** | L'écriture passe par un fichier temporaire, puis `fsync` et renommage : un plantage ne laisse jamais de coffre à moitié écrit. Seul le propriétaire peut lire le fichier. |

## Audit des mots de passe

`lockbox audit` signale les mots de passe :

- **courants** ;
- **courts ou faibles** ;
- **réutilisés** d'une entrée à l'autre ;
- **basés sur le nom d'utilisateur** ;
- **anciens**, non changés depuis plus d'un an ;
- **ayant fuité** (avec `--online`), vérifiés auprès de Have I Been Pwned grâce au **k-anonymat** : seuls les 5 premiers caractères hexadécimaux du SHA-1 du mot de passe sont envoyés, et la comparaison se fait localement.

## Installation et utilisation

```bash
git clone https://github.com/AlawiAhmedDev/lockbox.git
cd lockbox
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

lockbox init
lockbox add github --username alawi --generate
lockbox get github --clip
lockbox list
lockbox audit --online
lockbox passwd
```

La liste complète des commandes se trouve dans le [README anglais](README.md#commands).

## Modèle de menace

**Protège contre :**
- le vol du fichier du coffre, qui oblige l'attaquant à casser Argon2id ;
- toute modification du fichier, qui est détectée ;
- la fuite de mots de passe lors de la vérification des fuites, grâce au k-anonymat.

**Ne protège pas contre :**
- un ordinateur compromis (logiciel malveillant, keylogger) ;
- un mot de passe maître faible ;
- les secrets restés en mémoire, car Python ne peut pas les effacer de façon fiable ;
- le presse-papiers, qui n'est pas vidé automatiquement.

Lockbox est un projet d'apprentissage centré sur la cryptographie. Pour de vrais secrets, utilisez un gestionnaire audité comme KeePassXC ou Bitwarden.

## Tests

27 tests vérifient, au-delà du fonctionnement normal, que les attaques visées sont bien arrêtées :

- un mauvais mot de passe ;
- un bit modifié dans le chiffré ;
- des paramètres Argon2 abaissés ;
- un bloc de données échangé avec celui d'un autre coffre ;
- la réutilisation de nonce ;
- les permissions du fichier ;
- les mots de passe Unicode (arabe) ;
- la garantie de k-anonymat.

## Auteur

**Alawi Masfar**, Master en Intelligence Artificielle et Cybersécurité. GitHub : [@AlawiAhmedDev](https://github.com/AlawiAhmedDev)

## Licence

[MIT](LICENSE)
