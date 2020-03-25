<?php
require_once "./vendor/autoload.php";
require_once "./FileRepository.php";

use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;

$rpEntity = new PublicKeyCredentialRpEntity(
    'Webauthn Server',
    );

$publicKeyCredentialSourceRepository = new FileRepository();

$server = new Server(
    $rpEntity,
    $publicKeyCredentialSourceRepository,
    null
);

$psr17Factory = new Psr17Factory();
$creator = new ServerRequestCreator(
    $psr17Factory, // ServerRequestFactory
    $psr17Factory, // UriFactory
    $psr17Factory, // UploadedFileFactory
    $psr17Factory  // StreamFactory
);

$serverRequest = $creator->fromGlobals();
session_start();
try {
    $publicKeyCredentialSource = $server->loadAndCheckAttestationResponse(
        file_get_contents("php://input"),
        unserialize($_SESSION['creation']), // The options you stored during the previous step
        $serverRequest                       // The PSR-7 request
    );

    // The user entity and the public key credential source can now be stored using their repository
    // The Public Key Credential Source repository must implement Webauthn\PublicKeyCredentialSourceRepository
    $publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
    echo "success!";
} catch(\Throwable $exception) {
    var_dump($exception);
    // Something went wrong!
}