
# Desafio Backend

A implementação visa resolver o desafio levando os requisitos informados como consideração.

## Para executar o projeto

Após baixar o projeto, siga os comandos abaixo:

```
docker-compose up -d
cp .env.example .env
docker-compose exec app composer install
docker-compose exec app php artisan key:generate
docker-compose exec app php artisan migrate:refresh --seed
docker-compose exec app php artisan queue:work
```

## Testes

```
docker-compose exec app php artisan test
```

## Endpoint

```
(post) http://localhost/api/transaction
```

## Swagger

Após rodar o projeto, acessar o endereço:

```
http://localhost/swagger
```

## Melhorias de arquitetura

1. Utilização de serviço de mensageria (RabbitMQ, por exemplo) para as transações
2. Modelagem de uma carteira para armazenar métodos de pagamento
3. Log de todas as interações
4. Guardar as notificações enviadas

## Modelo

Modelo de dados básico necessário para resolução da arquitetura proposta

![alt text](https://github.com/zepaduajr/pp-desafio/blob/main/model.png?raw=true)
