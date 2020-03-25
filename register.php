<?php
require_once "./vendor/autoload.php";
require_once "./FileRepository.php";

use Webauthn\PublicKeyCredentialSource;
use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

if ($_POST['name']) {
    $rpEntity = new PublicKeyCredentialRpEntity(
            'Webauthn Server',
    );
    $userEntity = new PublicKeyCredentialUserEntity(
        $_POST['name'],
        $_POST['name'],
        strtoupper($_POST['name'])
    );
    $publicKeyCredentialSourceRepository = new FileRepository();
    $server = new Server(
        $rpEntity,
        $publicKeyCredentialSourceRepository,
        null
    );

    /** This avoids multiple registration of the same authenticator with the user account **/
    /** You can remove this code if it is a new user **/
    $credentialSources = $publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

    $excludeCredentials = array_map(function (PublicKeyCredentialSource $credential) {
        return $credential->getPublicKeyCredentialDescriptor();
    }, $credentialSources);

    $creation = $server->generatePublicKeyCredentialCreationOptions(
        $userEntity,
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        $excludeCredentials,
    );
    session_start();
    // store the creation for usage later
    $_SESSION['creation'] = serialize($creation);

    // add parameters required by js.
    $creation = array_merge([
        'user' => $userEntity,
        'pubKeyCredParams' => [
            [
                'type' => "public-key",
                'alg' => -7 // ES256
            ],
            [
                'type' => "public-key",
                'alg' => -257 // RS256
            ]
        ],
        'rp' => $rpEntity->jsonSerialize()
    ], $creation->jsonSerialize());
    ?>

    <html lang="">
    <head>
        <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <title>Register</title>
    </head>
    <body>
        <a href="/register.php"> To Register </a> <br>
        <a href="/login.php"> To Login </a>
    <script>
        publicKey = <?php echo json_encode($creation); ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        function base64url2base64(input) {
            input = input
                .replace(/=/g, "")
                .replace(/-/g, '+')
                .replace(/_/g, '/');

            const pad = input.length % 4;
            if (pad) {
                if (pad === 1) {
                    throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
                }
                input += new Array(5 - pad).join('=');
            }

            return input;
        }

        publicKey.challenge = Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)), function (c) {
            return c.charCodeAt(0);
        });
        publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), function (c) {
            return c.charCodeAt(0);
        });
        if (publicKey.excludeCredentials) {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map(function (data) {
                data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), function (c) {
                    return c.charCodeAt(0);
                });
                return data;
            });
        }

        navigator.credentials.create({'publicKey': publicKey})
            .then(function (data) {
                const publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject))
                    }
                };
                console.log(publicKeyCredential)
                axios.post("/do_register.php",publicKeyCredential).then(function(response){
                    console.log(response);
                    alert(response.data)
                });
            })
            .catch(function (error) {
                alert('Open your browser console!');
                console.log('FAIL', error);
            });

    </script>
    </body>
    </html>
<?php }else{ ?>
    <html lang="">
    <head>
        <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <title>Register</title>
    </head>
    <body>
    <form action="" method="POST">
        <input type="text" name="name"/>
        <input type="submit"/>
    </form>

    <a href="/register.php"> To Register </a> <br>
    <a href="/login.php"> To Login </a>
    </body>
    </html>
    <?php
}