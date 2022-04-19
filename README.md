Relying Party Resiliency Platform
=================================
The aim of this repository is to experiment with RPKI repositories and certificate authorities,
especially with the focus of causing unintended behaviour on relying party clients.

The theoretical underpinnings, architecture, etc. can be found here: 

> van Hove, K., van der Ham, J., & van Rijswijk-Deij, R. (2022). Rpkiller: Threat Analysis from an RPKI Relying Party Perspective. arXiv. https://doi.org/10.48550/ARXIV.2203.00993

Created by Koen van Hove (koen@koenvh.nl)

Commands
--------
Routinator:
```
routinator --tal-dir=. -vv vrps -f json -o vrps.json
```

OctoRPKI:
```
octorpki -loglevel=debug -mode=oneoff -rrdp.failover=false -output.sign=false -tal.root=koenvh.tal
```

Fort:
```
sudo fort --log.level=debug --validation-log.level=debug --validation-log.enabled=true --mode=standalone --tal=.
```

RPKI-Prover:
```
faketime '1 hour' rpki-prover
```
The time is set to the future, because rpki-prover checks the time before it requests the resources,
(I believe because time is a side effect in Haskell) which can cause an error because rpki-prover 
thinks the CRL was from the future. 

rpki-client:
```
sudo rpki-client -vv -t /etc/rpki/koenvh.tal
```

rpstir2:
```
sudo ./rpstir2
curl -s -k -d '{"syncStyle": "rrdp"}'  -H "Content-type: application/json" -X POST http://127.0.0.1:8070/sync/start
```
