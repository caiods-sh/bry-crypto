# Teste técnico Bry

## Comandos úteis

### Gerar certificados para testes
```bash
# Cria certificado key.pem e cert.pem
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes
```

```bash
# Empacota certificado e chave privada (cert_unit_test.pfx)
openssl pkcs12 -export -out cert_unit_test.pfx -inkey key.pem -in cert.pem
```