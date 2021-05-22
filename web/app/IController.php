<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class IController
{
    private string $domain = "i.rpki.koenvh.nl";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private string $state = "1";

    private const VIRUS_GROWTH = 10 + 1;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/i([^-]*)-([^.]+)\./', $this->domain, $matches);
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
        $uniqid = "roa-roa-roa-your-boat";

        $xml = new XMLWriter();
        $xml->openMemory();
        $xml->setIndent(true);
        $xml->startElement("notification");
        $xml->writeAttribute("version", "1");
        $xml->writeAttribute("session_id", $this->sessionId);
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("xmlns", "http://www.ripe.net/rpki/rrdp");
        $xml->startElement("snapshot");
        $xml->writeAttribute("uri", "https://$this->domain/$uniqid/snapshot.xml");
        $xml->writeAttribute("hash", hash("sha256", $this->snapshot($uniqid)->getBody()->getContents()));
        $xml->endElement();

        $xml->startElement("delta");
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("uri", "https://$this->domain/1337/delta.xml");
        $xml->writeAttribute("hash", hash("sha256", $this->delta("1337")->getBody()->getContents()));
        $xml->endElement();

        $xml->endElement();

        return new Response\TextResponse($xml->outputMemory(), 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }

    function snapshot($uniqid) {
        ini_set("memory_limit", "2048M");

        $openSSL = new OpenSSL();

        $firstRun = !$openSSL->retrieveManifest($this->domain, 1);
        if ($firstRun) {
            $initialCrl = $openSSL->generateCrl(
                $openSSL->retrieveCertificate($this->domain, 1),
                $openSSL->retrievePrivateKey($this->domain, 1),
                $this->domain
            );
            $openSSL->storeCrl($this->domain, $initialCrl, 1);

            $fileList = [
                [
                    "file" => "koenvh.crl",
                    "hash" => hash("sha256", base64_decode($openSSL->retrieveCrl($this->domain, 1)))
                ]
            ];

            for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
                $roa = $openSSL->generateBrokenRoa($i, [
                    "1.2.3.4/26",
                ], [
                    "2001:0db8:85a3:0000:1319:8a2e:0370:7344/51"
                ], $openSSL->retrievePrivateKey($this->domain), $this->domain, $this->domain, "koenvh", "koenvh");
                $openSSL->storeRoa($this->domain, $roa, $i);

                $fileList[] = [
                    "file" => "koenvh$i.roa",
                    "hash" => hash("sha256", base64_decode($roa))
                ];
            }

            $initialManifest = $openSSL->generateManifest($fileList, $openSSL->retrievePrivateKey($this->domain, 1), $this->domain, $this->domain, "koenvh", "koenvh");
            $openSSL->storeManifest($this->domain, $initialManifest, 1);
        }

        $xml = new XMLWriter();
        $xml->openMemory();
        $xml->setIndent(true);

        $xml->startElement("snapshot");
        $xml->writeAttribute("version", "1");
        $xml->writeAttribute("session_id", $this->sessionId);
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("xmlns", "http://www.ripe.net/rpki/rrdp");

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.cer");
        $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($this->domain, 1)));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.crl");
        $xml->writeRaw($openSSL->retrieveCrl($this->domain, 1));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.mft");
        $xml->writeRaw($openSSL->retrieveManifest($this->domain, 1));
        $xml->endElement();

        for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
            $xml->startElement("publish");
            $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh$i.roa");
            $xml->writeRaw($openSSL->retrieveRoa($this->domain, $i));
            $xml->endElement();
        }

        $xml->endElement();

        return new Response\TextResponse($xml->outputMemory(), 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }

    function delta($i) {
        return new Response\TextResponse("", 200, [
            "Content-Type" => "text/xml",
            "Last-Modified" => gmdate("D, d M Y H:i:s") . " GMT",
            "Expires" => gmdate("D, d M Y H:i:s") . " GMT",
            "Cache-Control" => "max-age=60"
        ]);
    }
}
