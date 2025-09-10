
Port in .env => 8090

symfony server:start --port=8090
php bin/console cache:clear

update entity
    1. php bin/console make:entity
    2. php bin/console make:migration
    3. php bin/console doctrine:migrations:migrate