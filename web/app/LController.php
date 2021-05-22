<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class LController
{
    private string $domain = "l.rpki.koenvh.nl";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private string $state = "1";

    private const VIRUS_GROWTH = 5;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/l([^-]*)-([^.]+)\./', $this->domain, $matches);
        if ($matches[1]) {
            $this->state = $matches[1];
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
        $uniqid = "who-are-you-gonna-call";

        $xml = new XMLWriter();
        $xml->openMemory();
        $xml->setIndent(true);
        $xml->startElement("notification");
        $xml->writeAttribute("version", "1");
        $xml->writeAttribute("session_id", $this->sessionId);
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("xmlns", "http://www.ripe.net/rpki/rrdp");
        $xml->startElement("snapshot");
        $xml->writeAttribute("uri", "https://ftp.snt.utwente.nl/pub/test/100000M");
        $xml->writeAttribute("hash", hash("sha256", "random2"));
        $xml->endElement();

        $xml->startElement("delta");
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("uri", "https://$this->domain/1337/delta.xml");
        $xml->writeAttribute("hash", hash("sha256", "random"));
        $xml->endElement();

        $xml->endElement();

        return new Response\TextResponse($xml->outputMemory(), 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }
}
