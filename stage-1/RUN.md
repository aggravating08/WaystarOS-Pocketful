# Pocketful Stage 1 Service

With Docker running, execute this command from this directory to build and start:

```sh
docker build -t pocketful-stage-1 . && docker run --rm -p 8080:8080 pocketful-stage-1
```

The service is available at `http://localhost:8080`; stop it with Ctrl-C.
It binds `0.0.0.0` and uses `PORT` (default `8080`). To use another port:

```sh
docker build -t pocketful-stage-1 . && docker run --rm -e PORT=8090 -p 8090:8090 pocketful-stage-1
```

Python and its standard library are included in the image; there are no additional
runtime network requirements. All writes are atomic and serialized under a central
transaction lock. Money is strictly conserved across all transfers, splits, and net settlements.
Five write endpoints enforce idempotency key semantics.

