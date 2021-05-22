<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class JController
{
    private string $domain = "j.rpki.koenvh.nl";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private string $state = "1";

    private const VIRUS_GROWTH = 2200;
    private const DUPLICATES = 1; //125_000;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/j([^-]*)-([^.]+)\./', $this->domain, $matches);
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
        $xml->writeAttribute("hash", $this->snapshot("parent")->getBody()->getContents());
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
        ini_set("memory_limit", "4096M");
        set_time_limit(30 * 60);

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
//                $ipv6 = [];
//                for ($l = 0; $l < pow(2, 0); $l++) {
//                    $lHex = str_pad(dechex($l), 4, "0", STR_PAD_LEFT);
//                    for ($k = 0; $k < pow(2, 16); $k++) {
//                        $ipv6[] = "2001:0db9:$lHex:" . str_pad(dechex($k), 4, "0", STR_PAD_LEFT) . ":85a3:85a3:0000:1319:8a2e/128";
//                    }
//                }
                $roa = $openSSL->generateRoa($i, [
                    "1.2.3.4/26",
                ], [
                    "2001:0db8:85a3:0000:1319:8a2e:0370:7344/51"
                ], $openSSL->retrievePrivateKey($this->domain), $this->domain, $this->domain, "koenvh$i-0", "koenvh");
                $openSSL->storeRoa($this->domain, $roa, $i);

                $hash = hash("sha256", base64_decode($roa));
                for ($j = 0; $j < self::DUPLICATES; $j++) {
                    $fileList[] = [
                        "file" => "koenvh$i-$j.roa",
                        "hash" => $hash
                    ];
                }
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

        $ctx = hash_init("sha256");
        if ($uniqid == "parent") {
            hash_update($ctx, $xml->outputMemory());
        } else {
            echo $xml->outputMemory();
        }

        for ($i = 1; $i < self::VIRUS_GROWTH; $i++) {
            $rawRoa = $openSSL->retrieveRoa($this->domain, $i);
            for ($j = 0; $j < self::DUPLICATES; $j++) {
                $str = '<publish uri="' . "rsync://$this->domain/repository/koenvh$i-$j.roa" . '">' . $rawRoa . '</publish>' . "\n";
                if ($uniqid == "parent") {
                    hash_update($ctx, $str);
                } else {
                    echo $str;
                }
//                $xml->startElement("publish");
//                $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh$i-$j.roa");
//                $xml->writeRaw($rawRoa);
//                $xml->endElement();
                flush();
            }
        }

        $str = "</snapshot>";
        if ($uniqid == "parent") {
            hash_update($ctx, $str);
        } else {
            echo $str;
        }
        //$xml->endElement();
        header("Content-Type: text/xml");

        return new Response\TextResponse($uniqid == "parent" ? hash_final($ctx, false) : "", 200, [
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
