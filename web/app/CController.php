<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class CController
{
    private string $domain = "c.rpki.koenvh.nl";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private int $number = 1;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/c(\d*)-([^.]+)\./', $this->domain, $matches);
        if ($matches[1]) {
            $this->number = (int)$matches[1];
        }
        $this->sessionId = $matches[2];
    }

    function tal() {
        $openSSL = new OpenSSL();

        if (!($content = $openSSL->retrieveTal($this->domain))) {
            $privateKey = null;
            $certificate = null;
            $openSSL->generateCertificate($this->domain, $certificate, $privateKey);
            $publicKey = $openSSL->getPublicKey($privateKey);
            $publicKey = $openSSL->stripPublicKey($publicKey);

            $content = "https://$this->domain/ta/ta.cer\nrsync://$this->domain/ta/ta.cer\n\n$publicKey";
            $openSSL->storePrivateKey($this->domain, $privateKey);
            $openSSL->storeCertificate($this->domain, $certificate);
            $openSSL->storeTal($this->domain, $content);
        }

        return new Response\TextResponse($content, 200, [
            "Content-Type" => "text/plain"
        ]);
    }

    function cer() {
        $openSSL = new OpenSSL();
        return new Response\TextResponse($openSSL->retrieveCertificate($this->domain), 200, [
            "Content-Type" => "application/octet-stream"
        ]);
    }

    function notification() {
        $uniqid = $this->number + 1;

        $newDomain = "https://c$uniqid-$this->sessionId." . DOMAIN . "/notification.xml";

        return new Response\RedirectResponse($newDomain);
    }
}
