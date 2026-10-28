# ct-audit
Auditoría constant-time de implementaciones ML-KEM / ML-DSA bajo distintos compiladores.

Código auditado (pq-crystals/kyber):
- b628ba7: Kyber ronda 3, vulnerable a clangover (control positivo)
- 9b8d306: fix de clangover (control negativo)
- d5b791c: rama standard (ML-KEM, FIPS 203)
