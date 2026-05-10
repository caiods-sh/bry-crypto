# Teste técnico Bry

## Dependências
O projeto possui um Dockerfile, é altamente recomendado utilizar o docker para evitar problemas com conflitos de dependências, versões de compiladores, etc...

Caso queira compilar e rodar a aplicação sem docker, segue lista das ferramentas que utilizei para o desenvolvimento do projeto:

- **Ubuntu: v25.10**
- **conan: v2.25.2**
- **cmake: v3.31.6**
- **g++: v15.2.0**
- **make: v4.4.1**

## Comandos
### Rodando a aplicação sem Docker.
> Primeiramente altere a variável "PROJECT_DIR" no Makefile, para o mesmo diretório que o projeto foi clonado.

```bash
# Instalar dependências.
make setup
```

```bash
# Compilar executáveis.
make build
```

```bash
# Executar API.
make run_api
```

```bash
# Executar script para gerar resumo criptográfico.
make run_challenge_one DOC_DIR=./resources/arquivos/doc.txt
```


### Rodar a aplicação com Docker.
```bash
# Buildar imagem
docker build -t bry-challenge .
```

```bash
# Rodar container
docker run -p 8080:8080 bry-challenge
```

### Gerar certificados para fins de teste.
```bash
# Cria certificado e chave privada (key.pem e cert.pem)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha512 -days 365 -nodes
```

```bash
# Empacota certificado e chave privada (cert_unit_test.pfx)
openssl pkcs12 -export -out cert_unit_test.pfx -inkey key.pem -in cert.pem
```
