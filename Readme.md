
Port in .env => 8090

symfony server:start --port=8090
php bin/console cache:clear

update entity
    1. php bin/console make:entity
    2. php bin/console make:migration
    3. php bin/console doctrine:migrations:migrate







The unique identity credentials you receive are confidential—keep them safe and do not share them with anyone.

corporate_id: cid_1vMBEIzH1WXM9yGpTfmpLXK9kV3qkouVBqq69GHdkTRMm4typ7e41AFo20Ve
corporate_id_key: ckey_i376ic1kWP0bDvatCWB+R1iOQV/jphTSC0j0tKWWBIFJyF6G+zaFoFhYCA2
corporate_id_secret: csec_KpMMbj5JVdsFTNO+3uiC4/9cnjbEYiXLcKguiIWkPEf16acWI2u8KZtmd7d
service_api_key: skey_bdHBPFljYNuhaIk5wTSihHDQXw8pdH64c2JvjPJVcJsX5pruAP/EkTBbk3A
service_api_secret: ssec_IoOOUU7PbYE/Ib98Rgw1bBPsUuk81tEhV9GIutvMGfK+JD2InYrUx7fOsMO
data_hash_secret: dsec_I9UZ9bEezYObQK2mxgfyceg4PTfblHAid4AJIA81QF6TIFBbjHkQH5bOluX  