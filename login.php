<?php
require_once "./vendor/autoload.php";
require_once "./FileRepository.php";
use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialSource;

if ($_POST['name']) {

    $rpEntity = new PublicKeyCredentialRpEntity(
        'Webauthn Server'
    );
    $userEntity = new PublicKeyCredentialUserEntity(
        $_POST['name'],
        $_POST['name'],
        strtoupper($_POST['name'])
    );

    $publicKeyCredentialSourceRepository = new FileRepository(); //Your repository here. Must implement

    $server = new Server(
        $rpEntity,
        $publicKeyCredentialSourceRepository,
        null
    );

// Get the list of authenticators associated to the user
    $credentialSources = $publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

// Convert the Credential Sources into Public Key Credential Descriptors
    $allowedCredentials = array_map(function (PublicKeyCredentialSource $credential) {
        return $credential->getPublicKeyCredentialDescriptor();
    }, $credentialSources);

// We generate the set of options.
    $publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED, // Default value
        $allowedCredentials
    );
    session_start();
    $_SESSION['request'] = serialize($publicKeyCredentialRequestOptions);
    ?>

    <html lang="">
    <head>
        <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <title>Login</title>
    </head>
    <body>
    <a href="/register.php"> To Register </a> <br>
    <a href="/login.php"> To Login </a>
    <script>
        publicKey = <?php echo json_encode($publicKeyCredentialRequestOptions); ?>;

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
        publicKey.challenge = Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)), function(c){return c.charCodeAt(0);});
        if (publicKey.allowCredentials) {
            publicKey.allowCredentials = publicKey.allowCredentials.map(function(data) {
                data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), function(c){return c.charCodeAt(0);});
                return data;
            });
        }
        console.log(publicKey);
        navigator.credentials.get({ 'publicKey': publicKey })
            .then(function(data){
                const publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        signature: arrayToBase64String(new Uint8Array(data.response.signature)),
                        userHandle: "<?php echo base64_encode($_POST['name']); ?>"
                    }
                };
                console.log(publicKeyCredential)
                axios.post("/do_login.php",publicKeyCredential).then(function(response){
                    console.log(response);
                    alert(response.data)
                });
            })
            .catch(function(error){
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
        <title>Login</title>
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