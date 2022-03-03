<?php

use MiladRahimi\PhpRouter\Router;
use MiladRahimi\PhpRouter\View\View;
use Ramsey\Uuid\Uuid;

require_once "../config.php";
require_once "../accounts.php";
require_once "../vendor/autoload.php";

$router = Router::create();
$router->setupView("../views");

$router->group(["domain" => DOMAIN, "middleware" => [\koenvh\RPKI\AuthRequest::class]], function(Router $router) {
    $router->any("/", function (View $view) {
        $uuid = Uuid::uuid4();
        return new \Laminas\Diactoros\Response\RedirectResponse("/$uuid");
    });
    $router->any("/{uuid}", function (View $view, $uuid) {
        return $view->make("index", ["uuid" => $uuid]);
    });
});

$router->group(["domain" => "ipv6." . DOMAIN], function (Router $router) {
    $router->any("/", function (View $view) {
        return new \Laminas\Diactoros\Response\JsonResponse(["ipv6" => true], 200, [
            "Access-Control-Allow-Origin" => "https://" . DOMAIN
        ]);
    });
});

$router->group(["domain" => "a(\d*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\AController::class, "tal"]);
    $router->any("/koenvh-A.tal", [\koenvh\RPKI\AController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\AController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\AController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\AController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\AController::class, "delta"]);
});

$router->group(["domain" => "b-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\BController::class, "tal"]);
    $router->any("/koenvh-B.tal", [\koenvh\RPKI\BController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\BController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\BController::class, "notification"]);
});

$router->group(["domain" => "c(\d*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\CController::class, "tal"]);
    $router->any("/koenvh-C.tal", [\koenvh\RPKI\CController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\CController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\CController::class, "notification"]);
});

$router->group(["domain" => "d-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\DController::class, "tal"]);
    $router->any("/koenvh-D.tal", [\koenvh\RPKI\DController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\DController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\DController::class, "notification"]);
});

$router->group(["domain" => "e-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\EController::class, "tal"]);
    $router->any("/koenvh-E.tal", [\koenvh\RPKI\EController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\EController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\EController::class, "notification"]);
});

$router->group(["domain" => "f(\d*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\FController::class, "tal"]);
    $router->any("/koenvh-F.tal", [\koenvh\RPKI\FController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\FController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\FController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\FController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\FController::class, "delta"]);
});

$router->group(["domain" => "g(\d*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\GController::class, "tal"]);
    $router->any("/koenvh-G.tal", [\koenvh\RPKI\GController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\GController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\GController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\GController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\GController::class, "delta"]);
});

$router->group(["domain" => "h([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\HController::class, "tal"]);
    $router->any("/koenvh-H.tal", [\koenvh\RPKI\HController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\HController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\HController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\HController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\HController::class, "delta"]);
});

$router->group(["domain" => "i([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\IController::class, "tal"]);
    $router->any("/koenvh-I.tal", [\koenvh\RPKI\IController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\IController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\IController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\IController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\IController::class, "delta"]);
});

$router->group(["domain" => "j([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\JController::class, "tal"]);
    $router->any("/koenvh-J.tal", [\koenvh\RPKI\JController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\JController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\JController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\JController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\JController::class, "delta"]);
});

$router->group(["domain" => "k([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\KController::class, "tal"]);
    $router->any("/koenvh-K.tal", [\koenvh\RPKI\KController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\KController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\KController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\KController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\KController::class, "delta"]);
});

$router->group(["domain" => "l([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\LController::class, "tal"]);
    $router->any("/koenvh-L.tal", [\koenvh\RPKI\LController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\LController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\LController::class, "notification"]);
    $router->any("/notification.dtd", [\koenvh\RPKI\LController::class, "dtd"]);
});

$router->group(["domain" => "m([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\MController::class, "tal"]);
    $router->any("/koenvh-M.tal", [\koenvh\RPKI\MController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\MController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\MController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\MController::class, "snapshot"]);
});

$router->group(["domain" => "n(\d*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\NController::class, "tal"]);
    $router->any("/koenvh-N.tal", [\koenvh\RPKI\NController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\NController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\NController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\NController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\NController::class, "delta"]);
});

$router->group(["domain" => "o(\d*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\OController::class, "tal"]);
    $router->any("/koenvh-O.tal", [\koenvh\RPKI\OController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\OController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\OController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\OController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\OController::class, "delta"]);
});

$router->group(["domain" => "p([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\PController::class, "tal"]);
    $router->any("/koenvh-P.tal", [\koenvh\RPKI\PController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\PController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\PController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\PController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\PController::class, "delta"]);
});

$router->group(["domain" => "p([^-]*)-(.*)." . DOMAIN, "middleware" => [\koenvh\RPKI\DumpHTTPRequest::class]], function(Router $router) {
    $router->any("/tal.tal", [\koenvh\RPKI\PController::class, "tal"]);
    $router->any("/koenvh-P.tal", [\koenvh\RPKI\PController::class, "tal"]);
    $router->any("/ta/ta.cer", [\koenvh\RPKI\PController::class, "cer"]);
    $router->any("/notification.xml", [\koenvh\RPKI\PController::class, "notification"]);
    $router->any("/{uniqid}/snapshot.xml", [\koenvh\RPKI\PController::class, "snapshot"]);
    $router->any("/{i}/delta.xml", [\koenvh\RPKI\PController::class, "delta"]);
});

try {
    $router->dispatch();
} catch (\MiladRahimi\PhpRouter\Exceptions\InvalidCallableException $e) {
} catch (\MiladRahimi\PhpRouter\Exceptions\RouteNotFoundException $e) {
    return "404 - this resource does not exist";
}
