<?php
require_once "./vendor/autoload.php";
require_once "./FileRepository.php";

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;

$psr17Factory = new Psr17Factory();
$creator = new ServerRequestCreator(
    $psr17Factory, // ServerRequestFactory
    $psr17Factory, // UriFactory
    $psr17Factory, // UploadedFileFactory
    $psr17Factory  // StreamFactory
);

$serverRequest = $creator->fromGlobals();

$rpEntity = new PublicKeyCredentialRpEntity(
    'Webauthn Server',
);


$publicKeyCredentialSourceRepository = new FileRepository(); //Your repository here. Must implement

$server = new Server(
    $rpEntity,
    $publicKeyCredentialSourceRepository,
    null
);
session_start();
try {
    $publicKeyCredentialSource = $server->loadAndCheckAssertionResponse(
        file_get_contents("php://input"),
        unserialize($_SESSION['request']), // The options you stored during the previous step
        null,                        // The user entity
        $serverRequest,                      // The PSR-7 request
    );
    echo "successfully logged as ". $publicKeyCredentialSource->getUserHandle();
} catch(\Throwable $exception) {
    print_r($exception);
}