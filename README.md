# corswhy

**Un fichier PHP. Zéro dépendance. Il dit pourquoi le navigateur a bloqué ta requête, et il te donne le correctif.**

`Failed to fetch` ne dit rien. corswhy parle le [standard Fetch](https://fetch.spec.whatwg.org/#http-cors-protocol) : préflight, cookies contre `*`, `Authorization` que le joker ne couvre jamais, et les en-têtes exacts à renvoyer.

```text
corswhy  PATCH https://api.example.com/users
origin   https://app.example.com
cookies  include
preflight yes — method PATCH, authorization, content-type

BLOCKED    The browser will not let JavaScript read this response.

  fatal  Wildcard with credentials
         Access-Control-Allow-Origin: * cannot be used with cookies.
  fatal  Authorization is special
         * does not cover Authorization. List it explicitly.
```

Anglais par défaut, `--lang fr` pour le diagnostic en français. Puis un snippet PHP et Nginx collables.

## Pourquoi celui-ci

La plupart des testeurs CORS répètent des mythes. corswhy suit la spec :

| Ce qu'on croit | Ce que fait le navigateur |
| --- | --- |
| `Access-Control-Allow-Origin: *` marche avec des cookies | Bloqué. Il faut l'origine exacte et `Access-Control-Allow-Credentials: true`. |
| On peut lister plusieurs origines dans un seul en-tête | Non. Une origine, ou `*`. Jamais `https://a.com, https://b.com`. |
| `Access-Control-Allow-Headers: *` autorise `Authorization` | Non. `Authorization` doit être cité par son nom, avec ou sans cookies. |
| Avec des cookies, `*` veut dire « tout » | Non. `*` redevient le nom littéral `*`. |
| Un OPTIONS 404 avec les bons en-têtes suffit | Non. Le préflight doit être un statut 200–299. |
| `POST` doit être dans `Allow-Methods` | Non. `GET`, `HEAD` et `POST` sont des méthodes simples. |
| `Content-Type: application/json` est une requête simple | Non. Ça déclenche un préflight. `text/plain` non. |
| Le préflight a réussi, donc c'est bon | Non. La vraie réponse a aussi besoin de ses en-têtes CORS. |

## Usage

PHP 8.1 ou plus. `ext-curl` est utilisé s'il est là, sinon les flux HTTP de PHP.

```bash
php corswhy.php --origin https://app.example.com https://api.example.com/users

php corswhy.php \
  --origin https://app.example.com \
  --method POST \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer …" \
  --credentials \
  https://api.example.com/users

php corswhy.php --lang fr --demo
php corswhy.php --json --origin https://app.example.com https://api.example.com/health
```

`--origin` est l'origine de la page (ce que le navigateur met dans `Origin`), pas l'URL de l'API.

Codes de sortie : `0` autorisé, `1` bloqué, `2` usage ou réseau. Pratique en CI.

Les redirections ne sont pas suivies. Un 3xx est un diagnostic : chaque saut doit porter ses propres en-têtes CORS, et un préflight redirigé échoue.

## Correctif

Pour une requête avec cookies, la sortie ressemble à ceci (l'origine est la tienne) :

```php
$allowed = ['https://app.example.com'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowed, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Credentials: true');
}

header('Access-Control-Allow-Methods: PATCH, OPTIONS');
header('Access-Control-Allow-Headers: authorization, content-type');
header('Access-Control-Max-Age: 600');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}
```

Ne recopie pas n'importe quel `Origin` si des cookies sont en jeu. Une liste blanche, une origine renvoyée.

## Tester

```bash
php tests/self-test.php
php corswhy.php --demo
```

Le jeu de tests couvre les cas ci-dessus sans réseau, puis une requête réelle vers `https://example.com` quand le réseau répond.

## Usage responsable

N'interroge que des API que tu as le droit de tester. L'outil envoie un `OPTIONS` (seulement si le navigateur le ferait) et, si ce préflight passerait, une seule vraie requête. Le jeton `Authorization` part sur cette vraie requête, comme dans un navigateur, jamais sur le préflight. Il n'est pas réaffiché.

## English

corswhy is a single PHP file that explains a CORS failure the way the Fetch standard does, then prints a PHP and Nginx fix. Default output is English. `--lang fr` switches the diagnosis to French.

## Licence

MIT.
