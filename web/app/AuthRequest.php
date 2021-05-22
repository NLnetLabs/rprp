<?php

namespace koenvh\RPKI;

use Laminas\Diactoros\Response;
use MiladRahimi\PhpRouter\View\View;
use Psr\Http\Message\ServerRequestInterface;
use Ramsey\Uuid\Uuid;

class AuthRequest {
    private function login()
    {
        if (isset(ACCOUNTS[$_SERVER["PHP_AUTH_USER"]])) {
            return password_verify($_SERVER["PHP_AUTH_PW"], ACCOUNTS[$_SERVER["PHP_AUTH_USER"]]);
        }
        return false;
    }

    public function handle(ServerRequestInterface $request, \Closure $next)
    {
        if (!isset($_SERVER['PHP_AUTH_USER']) || !$this->login()) {
            $msg = file_get_contents(dirname(__FILE__) . "/../views/request-access.phtml");
            return new Response\HtmlResponse($msg, 401, [
                "WWW-Authenticate" => 'Basic realm="Relying Party Resiliency Platform"'
            ]);
        } else {
            return $next($request);
        }
    }
}
